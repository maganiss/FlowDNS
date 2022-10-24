// Go program to correlate Netflow records with DNS records. 
// Input: 	Config file in json format, template to be found in /configs/templates/go-conf.json
//		It reads from the DNS stream and Netflow streams provided in the config file.
// Output:	This script puts the correlated results into *.gz files. 
// 		Each line in the .gz output has PEER_SRC_IP, IN_IFACE, SRCIP, DSTIP, PACKETS, BYTES, plus two columns:
//		 - multiple flag (specifying whether the next item is a probable match (multiple = 1) or a definite match(multiple = 0)
//		 - an array of domains found in the dns records. 
package main

import (
	"io"
	"io/ioutil"
	"encoding/gob"
	"bytes"
	"runtime"
	"fmt"
	"os"
	"bufio"
	"concurrent-map"
	"strings"
	"strconv"
	"compress/gzip"
	"time"
    "log"
	"encoding/json"
	"net"
	"encoding/hex"
)

var last_ts []int
var last_ts_long []int
var last_cts int = 0
var last_cts_long int = 0

// class to keep the configurations specified in the go-conf.json
type Configuration struct {
	NumSplit int
	NumCols    int
	RouterIndex int
	InifaceIndex int
	SrcipIndex   int
	DstipIndex int
	TimestampIndex   int
	PacketsIndex int
	BytesIndex int
	DNSPipes []string
	NetflowPipes []string
	OutPath string
	CNAME_ClearUpInterval int
	A_ClearUpInterval int
	CDNs []string
	NumFillUpWorkers int
	NumLookUpWorkers int
	NumWriteWorkers int
	DnsQBufferSize int
	NetflowQBufferSize int
	WriteQBufferSize int
}

// class to keep all required information for a DNS jobs to be passed to fillUpWorker.
// 	- ts: Timestamp of the DNS record
//	- query: A/AAAA records or CNAME queried.
//	- rtype: 1 for A, 28 for AAAA, 5 for CNAME
//	- answer: IP in A/AAAA records, A/AAAA name in CNAMEs.
type DnsJob struct {
	ts int
	query string
	rtype string
	ttl int 
	answer string
}

// Converts compressed IPv6 format to uncompressed
func FullIPv6(ip net.IP) string {
	if ip.To16() == nil {
		return ""
	}
	dst := make([]byte, hex.EncodedLen(len(ip)))
	_ = hex.Encode(dst, ip)
	return string(dst[12:16])
}

// Given an IP address, specifies the split to which it should be allocated.
// The function takes the last octet/hextet from IP, and divides it into NumSplit splits.
func label(ip string, NumSplit int) int {
	if strings.Contains(ip,":")  {
		ipnew :=  FullIPv6(net.ParseIP(ip))
		if ipnew == "" {
			return -1
		}
		lastbyteInt, err:=strconv.ParseInt(ipnew,16,32)
		if err != nil {
			return -1
		}
		res:=int(lastbyteInt) % NumSplit
		return res
	} else if strings.Contains(ip,".") {
		split:=strings.Split(ip,".")
                lastbyte:=split[len(split)-1]
		lastbyteInt, err:=strconv.Atoi(lastbyte)
		if err != nil {
                        return -1
                }
                res:=int(lastbyteInt) % NumSplit
                return res
	} else {return -1}
}

// The core function to fill given hashmap with the given key and value.
// The key is always one item, either IP or A/AAAA name.
// The value is always an array with the length of len(conf.CDNs)+1.
// It prioritizes the conf.CDNs in the way that it allocates specific indexes in the value array of the hashmaps to specific CDNs. 
// If no desired CDN is found in the valueItem, just puts it in the last index of the value array.
func fillup (hm cmap.ConcurrentMap, key string, valueItem string, conf Configuration) cmap.ConcurrentMap{
        if key == valueItem {
                return hm
        }
	found := false
	newVal := make([]string, len(conf.CDNs)+1)
	for  i := range conf.CDNs {
		if strings.Contains(valueItem, conf.CDNs[i]){
			newVal[i] = valueItem
			found = true
			break
		}
	}
	// If the valueItem is not among the desired conf.CDNs, just add the valueItem to the end of array.
	if !found {
		/*
		tnum := <- numRecs 
		tnum++
		numRecs <- tnum
		if tnum % 10000 == 0 { fmt.Println("--------",tnum)}
		*/
		newVal[len(newVal) -1] = valueItem
	}
	hm.Set(key,newVal)
	return hm
}


// The core function to look up a specific key, be it IP address or A/AAAA name, in the hashmap.
func singleLookup(hm cmap.ConcurrentMap, key string)([]string, bool){
        var results []string
        multiple := false
        cnt := 0
        if tmparr, ok := hm.Get(key); ok{
                arr := tmparr.([]string)
                // Check if the value has more than one non-empty items.
		for i := range arr {
                        if len(arr[i]) > 0 {
                                cnt++
                                if cnt >1 {
                                        multiple = true
                                        break
                                }
                        }
                }
		// check if the specific indexes allocated to conf.CDNs are non-empty. If yes, adds it to the results.
                for i := 0; i < len(arr)-1; i++ {
                        if arr[i] != "" {
                                results = append(results, arr[i])
                        }
                }

		// if there is no record with desired conf.CDNs is found, just put the last item of the array in the results.
	        if len(results) == 0 && arr[len(arr)-1] != "" {
			results = append(results, arr[len(arr)-1])
		}
        }
        return results, multiple
}


// For each lookup, we need to do three lookups: first in the current hashmap (active), then in the backup hashmap (passive), then in the long hashmap.
func deepLookup(hm cmap.ConcurrentMap, hm_backup cmap.ConcurrentMap, hm_long cmap.ConcurrentMap, hm_long_backup cmap.ConcurrentMap, key string)([]string, bool){
	results, multiple := singleLookup(hm, key)
	if len(results) == 0 {
		results, multiple = singleLookup(hm_backup, key)
		if len(results) == 0 {
			results, multiple = singleLookup(hm_long, key)
			if len(results) == 0{
				results, multiple = singleLookup(hm_long_backup, key)
			}
		}
	}
	return results, multiple
}

// For each netflow record, 
func lookup(hm_ip cmap.ConcurrentMap, hm_ip_backup cmap.ConcurrentMap, hm_ip_long cmap.ConcurrentMap,hm_ip_long_backup cmap.ConcurrentMap,  hm_cname cmap.ConcurrentMap, hm_cname_backup cmap.ConcurrentMap, hm_cname_long cmap.ConcurrentMap, hm_cname_long_backup cmap.ConcurrentMap, ip string,conf Configuration)([]string, string){
        var results []string
        finalmultiple := false
        multiplestr := "0"

        //checks if ip is in any of the hm_ip* maps
        arecs, multiple := deepLookup(hm_ip, hm_ip_backup, hm_ip_long, hm_ip_long_backup,ip)
        if len(arecs) != 0 {results = append(results, arecs...)}
        finalmultiple = finalmultiple || multiple
        var crecs []string

	// Lookup each single arec returned by the first lookup in the hm_cname* maps
        for _, arec := range arecs {
                crecs, multiple = deepLookup(hm_cname, hm_cname_backup, hm_cname_long, hm_cname_long_backup, arec)
                if len(crecs) != 0 {results = append(results, crecs...)}
                finalmultiple = finalmultiple || multiple
        }

	// follow the CNAME chain for all the results returned from the last cname lookup.
	// Since the number of crecs returned by each lookup can be more than one, add it a lookupQ and do while it's non-empty.
        /*
	var lookupQ []string
        lookupQ = append(lookupQ, crecs...)
        for len(lookupQ) != 0 {
                crec := lookupQ[0]
                lookupQ = lookupQ[1:]
		if crec == ""   {continue}
                results = append(results, crec)
                loopCount := 0
                for true {
			//print("<",ip,">")
                        var crecs_tmp []string
                        crecs_tmp, multiple = deepLookup(hm_cname, hm_cname_backup, hm_cname_long, crec)
                        finalmultiple = multiple || finalmultiple
                        if len(crecs_tmp)  != 0 && loopCount < 6{
                                crec = crecs_tmp[0]
                                results = append(results, crec)
                                lookupQ = append(lookupQ, crecs_tmp[1:]...)
                        } else {break}
			loopCount++
                }
        }*/

        for _, crec := range crecs {
                n1crecs,multiple := deepLookup(hm_cname, hm_cname_backup, hm_cname_long, hm_cname_long_backup, crec)
                finalmultiple = multiple || finalmultiple
                for _, n1crec := range n1crecs {
                        n2crecs,multiple := deepLookup(hm_cname, hm_cname_backup, hm_cname_long, hm_cname_long_backup,n1crec)
                        finalmultiple = multiple || finalmultiple
                        results = append(results,n1crec)
                        for _, n2crec := range n2crecs {
                                n3crecs,multiple := deepLookup(hm_cname, hm_cname_backup, hm_cname_long,hm_cname_long_backup, n2crec)
                                finalmultiple = multiple || finalmultiple
                                fillup(hm_cname,crec,n2crec,conf)
                                results = append(results,n2crec)
                                for _, n3crec := range n3crecs {
                                        n4crecs,multiple := deepLookup(hm_cname, hm_cname_backup, hm_cname_long, hm_cname_long_backup,n3crec)
                                        finalmultiple = multiple || finalmultiple
                                        fillup(hm_cname,crec,n3crec,conf)
                                        results = append(results,n3crec)
                                        for _, n4crec := range n4crecs {
                                                n5crecs,multiple := deepLookup(hm_cname, hm_cname_backup, hm_cname_long, hm_cname_long_backup,n4crec)
                                                finalmultiple = multiple || finalmultiple
                                                fillup(hm_cname,crec,n4crec,conf)
                                                results = append(results,n4crec)
                                                for _,n5crec := range n5crecs {
                                                        fillup(hm_cname,crec,n5crec,conf)
                                                        results = append(results,n5crec)
                                                }
                                        }
                                }
                        }
                }
        }

        if finalmultiple { multiplestr = "1"} else {multiplestr = "0"}
        return results, multiplestr
}

// class to keep active and passive hashmaps. 
//	- hm is the active buffer to which we write whenever a record arrives
//	- hm_backup is the passive buffer to which the passive hashmap will be flushed every *_ClearUpInterval seconds.
//	- hm_long is the buffer to keep any record that has a TTL > *_ClearUpInterval
type DnsDB struct {
        hm cmap.ConcurrentMap
        hm_backup cmap.ConcurrentMap
        hm_long cmap.ConcurrentMap
        hm_long_backup cmap.ConcurrentMap
}

func getRealSizeOf(v interface{}) (int, error) {
    b := new(bytes.Buffer)
    if err := gob.NewEncoder(b).Encode(v); err != nil {
        return 0, err
    }
    return b.Len(), nil
}

// Reads the DNS records and passes them to the corresponding fillUpWorker to be added to hm_ip* and hm_cname* maps.
func readDNS(passive bool, finished chan bool, ipdb []DnsDB, cnamedb []DnsDB, inpath string, is_gz bool, conf Configuration, fillUpQ chan DnsJob){//fillUpQs []chan DnsJob) {
	f,err := os.Open(inpath)
	//f,err := os.Open("/dev/stdin")
	if err != nil {
	fmt.Println(err)
	return
	}
	defer f.Close()
	var r *bufio.Reader
	if is_gz {
		gz,_ := gzip.NewReader(f)
		r = bufio.NewReaderSize(gz, 32*1024)
	} else {
		r = bufio.NewReaderSize(f, 32*1024)
	}
	linecount := 0
	lastepoch := time.Now().Unix()

	for true {
		for line, isPrefix, err := r.ReadLine();err == nil;line, isPrefix, err = r.ReadLine() {
			s := string(line)
			if isPrefix {print("DNSread: Buffer size overflow for line %v",s)} //meaning the buffer was too small and the line is only a prefix of the actual line
			linecount ++
			if linecount % 10000 == 0 {
				print(".")
				//PrintMemUsage()  
				//runtime.GC() 
			}
			// Print the number of items in each hashmap.
			if linecount % 1000000 == 0 {
				fmt.Println("1M dns records processed in ", time.Now().Unix() - lastepoch)
				lastepoch = time.Now().Unix()
				linecount = 0
				countstr := ""
				for i := 0; i < conf.NumSplit; i++ {
					newNums := fmt.Sprintf("hm_ip_%d = %d, ",i,ipdb[i].hm.Count()) +
							fmt.Sprintf("hm_ip_backup_%d = %d, ",i,ipdb[i].hm_backup.Count()) +
							fmt.Sprintf("hm_ip_long_%d = %d, ",i,ipdb[i].hm_long.Count()) +
							fmt.Sprintf("hm_ip_long_backup_%d = %d\n",i,ipdb[i].hm_long_backup.Count())
					countstr = countstr + "\t" + newNums
					iphmSize,err := getRealSizeOf(ipdb[i].hm.Items()) 
					if err != nil {log.Println("error! size could not be calculated")}
					iphmbSize,err := getRealSizeOf(ipdb[i].hm_backup.Items()) 
					if err != nil {log.Println("error! size could not be calculated")}
					iphmlSize,err := getRealSizeOf(ipdb[i].hm_long.Items()) 
					if err != nil {log.Println("error! size could not be calculated")}
					iphmlbSize,err := getRealSizeOf(ipdb[i].hm_long_backup.Items()) 
					if err != nil {log.Println("error! size could not be calculated")}
					newSizes := fmt.Sprintf("hm_ip_%d = %d, ",i,iphmSize) +
							fmt.Sprintf("hm_ip_backup_%d = %d, ",i,iphmbSize) +
							fmt.Sprintf("hm_ip_long_%d = %d, ",i,iphmlSize) +
							fmt.Sprintf("hm_ip_backup_long_%d = %d\n",i,iphmlbSize)
					log.Printf("ipnumEntries: %s",newNums)
					log.Printf("iphmSizes: %s",newSizes)
				}
				newNumsCname := fmt.Sprintf("hm_cname = %d, ",cnamedb[0].hm.Count()) +
						fmt.Sprintf("hm_cname_backup = %d, ",cnamedb[0].hm_backup.Count()) +
						fmt.Sprintf("hm_cname_long = %d, ",cnamedb[0].hm_long.Count()) +
						fmt.Sprintf("hm_cname_long_backup = %d, ",cnamedb[0].hm_long_backup.Count())
				countstr = countstr + "\t" + newNumsCname
				fmt.Printf("num of entries in \n%s", countstr)

				chmSize,err := getRealSizeOf(cnamedb[0].hm.Items()) 
				if err != nil {log.Println("error! size could not be calculated")}
				chmbSize,err := getRealSizeOf(cnamedb[0].hm_backup.Items()) 
				if err != nil {log.Println("error! size could not be calculated")}
				chmlSize,err := getRealSizeOf(cnamedb[0].hm_long.Items()) 
				if err != nil {log.Println("error! size could not be calculated")}
				chmlbSize,err := getRealSizeOf(cnamedb[0].hm_long_backup.Items()) 
				if err != nil {log.Println("error! size could not be calculated")}
				newSizes := fmt.Sprintf("hm_cname = %d, ",chmSize) +
						fmt.Sprintf("hm_cname_backup = %d, ",chmbSize) +
						fmt.Sprintf("hm_cname_long = %d, ",chmlSize) +
						fmt.Sprintf("hm_cname_backup_long = %d\n",chmlbSize)
				log.Printf("cnumEntries: %s",newNumsCname)
				log.Printf("chmSizes: %s",newSizes)


			}
			// Skip headers
			if strings.Contains(s,"#timestamp") {continue}
			columns := strings.Split(s, ",")

			// Skip dns records which don't contain responses.
			if len(columns) <= 7 {continue}
			cur_ts, err := strconv.Atoi(columns[0])
			if err != nil {continue}
			if cur_ts > 9000000000 || cur_ts < 1000000000 {continue}

			// explode each dns record line into the responses found in it.
			for _, answer := range columns[7:] {
				answer_cols := strings.Split(answer, ";") //answer_cols = [query, rrtype,ttl,answer]
				if len(answer_cols) != 4 {continue}
				ttl , err := strconv.Atoi(answer_cols[2])
				if err != nil {continue}
				query := strings.ToLower(answer_cols[0])
				answer := strings.ToLower(answer_cols[3])
				rtype := answer_cols[1]
				// Add the dns response to corresponding fillUpQ which will then be passed to fillUpWorker.
				fillUpQ <-DnsJob{cur_ts,query,rtype,ttl, answer}
				/*
				if rtype == "1" || rtype == "28" {
					if len(answer) < 3 {continue}
					lbl := label(answer,NumSplit)
					fillUpQs[lbl] <- DnsJob{cur_ts,query,rtype,ttl, answer}
				} else if rtype == "5" {
					for i := range fillUpQs {
						fillUpQs[i] <- DnsJob{cur_ts, query, rtype, ttl, answer}
					}
				} else {continue}
				*/
			}
		}
		fmt.Println("exited the inner dns reader loop")
		if passive {break}
	}
	if err != io.EOF && err != nil {
		fmt.Println(err)
		return
	}
	finished <- true
}


// Looks up the netflow srcip in the hashmaps and writes the results to wjobs. wjobs will be read by writeWorker.
/*
func nfLookup(columns []string,ipdb DnsDB, cnamedb DnsDB, parser string, wjobs chan <- []string, conf Configuration){
	hm_ip, hm_ip_backup, hm_ip_long := ipdb.hm, ipdb.hm_backup, ipdb.hm_long
	hm_cname, hm_cname_backup, hm_cname_long := cnamedb.hm, cnamedb.hm_backup, cnamedb.hm_long
	results, multiple := lookup(hm_ip, hm_ip_backup, hm_ip_long, hm_cname, hm_cname_backup, hm_cname_long, columns[conf.SrcipIndex],conf)
	if len(results) != 0 {
		tobewritten := strings.Join(columns,"\t") + "\t" + multiple + "\t['" + strings.Join(results,"','") + "']\n"
		wjobs <- []string{tobewritten,columns[conf.TimestampIndex]}
	}
}
*/
func lookUpWorker(ipdb []DnsDB, cnamedb []DnsDB, ljobs <-chan []string, wjobs chan <- []string, conf Configuration){
	lineCount := 0
	for true {
		for columns := range ljobs {
			if lineCount % 10000 == 0{
				fmt.Printf("l%d:",len(ljobs))
			}
			lineCount++
                        hm_cname, hm_cname_backup,hm_cname_long, hm_cname_long_backup := cnamedb[0].hm, cnamedb[0].hm_backup, cnamedb[0].hm_long, cnamedb[0].hm_long_backup
			lbl := label(columns[conf.SrcipIndex], conf.NumSplit)
			if lbl < 0 {
				break
			}
		        results, multiple := lookup(ipdb[lbl].hm, ipdb[lbl].hm_backup, ipdb[lbl].hm_long, ipdb[lbl].hm_long_backup, hm_cname, hm_cname_backup, hm_cname_long, hm_cname_long_backup, columns[conf.SrcipIndex],conf)
			if len(results) == 0 {continue}
			bucketCols := []string{columns[conf.RouterIndex],columns[conf.InifaceIndex],columns[conf.SrcipIndex],columns[conf.DstipIndex],columns[conf.TimestampIndex],columns[conf.PacketsIndex],columns[conf.BytesIndex]}
		        tobewritten := strings.Join(bucketCols,"\t") + "\t" + multiple + "\t['" + strings.Join(results,"','") + "']\n"
		        wjobs <- []string{tobewritten,columns[conf.TimestampIndex]}
		}
	}
}

// Clears up the active hashmap. (Second part of flushing the active buffer to passive buffer)
func clearUp(db DnsDB){
	tmpdb := db
	db = DnsDB{hm:cmap.New(), hm_backup: tmpdb.hm, hm_long: tmpdb.hm_long,hm_long_backup: tmpdb.hm_long_backup}
}

// reads from fjobs which is populated by readDNS and fills the hashmaps. It also takes care of flushing active buffer to passive buffer.
func fillUpWorker(workerID int, ipdb []DnsDB, cnamedb []DnsDB, fjobs <-chan DnsJob, conf Configuration){
	max_ts,lineCount := 0,0
	for true {
		for j := range fjobs {
			if lineCount % 10000 == 0{
				fmt.Printf("f%d|",len(fjobs))
			}
			lineCount++
			//tipdb := <-ipdb
			//ipdb <- tipdb
			//tcdb := <-cnamedb
			//cnamedb <- tcdb
			//hm_cname, hm_cname_backup,hm_cname_long := tcdb.hm, tcdb.hm_backup, tcdb.hm_long
			cur_ts, query, rtype, ttl, answer := j.ts,j.query,j.rtype,j.ttl,j.answer
			if rtype == "28" || rtype == "1" {
				lbl := label(answer, conf.NumSplit)
				if lbl < 0 {
					fmt.Printf("lbl < 0 for %s and label=%d\n", answer,lbl)
					continue
				}
				//hm_ip, hm_ip_backup, hm_ip_long := tipdb[lbl].hm, tipdb[lbl].hm_backup,tipdb[lbl].hm_long
				if cur_ts > max_ts {//&& (cur_ts - max_ts[lbl] < 60 || max_ts[lbl] == 0) {
					max_ts = cur_ts
					if cur_ts - last_ts[lbl] > conf.A_ClearUpInterval { //TODO: should be 60*10
						fmt.Printf("\nA/AAAA map %d \n",lbl)
						fmt.Printf("last_ts[%d] before: %d\n", lbl,last_ts[lbl])
						print("Clearing Started...\n")
						//clearUp(ipdb[lbl])
						ipdb[lbl].hm_backup = ipdb[lbl].hm
						ipdb[lbl].hm = cmap.New()
						fmt.Println(ipdb[lbl].hm.Count())
						fmt.Println(ipdb[lbl].hm_backup.Count())
						print("Clearing Finished...\n")
						last_ts[lbl] = cur_ts
						fmt.Printf("last_ts[%d] after: %d\n", lbl,last_ts[lbl])
					}
					if cur_ts - last_ts_long[lbl] > conf.A_ClearUpInterval * 72 {
						ipdb[lbl].hm_long_backup = ipdb[lbl].hm_long
						ipdb[lbl].hm_long = cmap.New()
						last_ts_long[lbl] = cur_ts
					}

				}
				if ttl > conf.CNAME_ClearUpInterval {
					ipdb[lbl].hm_long = fillup(ipdb[lbl].hm_long, answer, query, conf)
				} else {
					ipdb[lbl].hm = fillup(ipdb[lbl].hm, answer, query, conf)
					//fillup(hm_ip_backup[lbl], answer, query)
				}
				ipdb[lbl] = DnsDB{ipdb[lbl].hm,ipdb[lbl].hm_backup,ipdb[lbl].hm_long,ipdb[lbl].hm_long_backup}
				/*
				if lineCount % 10000 == 0{
					//fmt.Printf("workerID=%d, ipdb0=%d, ipdb1=%d, ipdb2=%d\n",workerID, ipdb[0].hm.Count(),ipdb[1].hm.Count(),ipdb[2].hm.Count())
					fmt.Println("workerID",workerID,"ipdb0",ipdb[0].hm,ipdb[1].hm,ipdb[2].hm)
				}*/
			} else if rtype == "5" {
				if ttl > conf.CNAME_ClearUpInterval {
					cnamedb[0].hm_long = fillup(cnamedb[0].hm_long, answer, query, conf)
				} else {
					cnamedb[0].hm = fillup(cnamedb[0].hm, answer, query, conf)
				}
				if cur_ts > max_ts {//&& (cur_ts - max_cts < 60 || max_cts == 0){
					max_ts = cur_ts
					if cur_ts - last_cts > conf.CNAME_ClearUpInterval { //TODO: should be 60*15
						fmt.Printf("\nCNAME map \n")
						print("Clearing Started...\n")
						//db := make(chan DnsDB, 1)
						//db <- DnsDB{hm:tcdb.hm,hm_backup:tcdb.hm_backup,hm_long:tcdb.hm_long}
						//clearUp(cnamedb)
						if cnamedb[0].hm.Count() != 0 {
							cnamedb[0].hm_backup =  cnamedb[0].hm
							cnamedb[0].hm = cmap.New()
							fmt.Println("hm_cname len: ",cnamedb[0].hm.Count())
							fmt.Println("hm_cname_backup len: ",cnamedb[0].hm_backup.Count())
							print("Clearing Finished.\n")
						}
						last_cts = cur_ts
						fmt.Println("last_cts: ", last_cts)
					}
					if cur_ts - last_cts_long > conf.A_ClearUpInterval * 72 {
						cnamedb[0].hm_long_backup = cnamedb[0].hm_long
						cnamedb[0].hm_long = cmap.New()
						last_cts_long = cur_ts
					}
				}
				cnamedb[0] = DnsDB{cnamedb[0].hm, cnamedb[0].hm_backup, cnamedb[0].hm_long,cnamedb[0].hm_long_backup}
			}
			//<-ipdb
			//toutipdb := make([]DnsDB, conf.NumSplit)
			//for i:=0; i<conf.NumSplit; i++ {
			//	toutipdb[i] = DnsDB{tipdb[i].hm, tipdb[i].hm_backup,tipdb[i].hm_long}
			//}
			//ipdb <- toutipdb
			//ipdb <- DnsDB{hm_ip, hm_ip_backup}
			//<-cnamedb
			//cnamedb <- DnsDB{tcdb.hm,tcdb.hm_backup, tcdb.hm_long}
			//<-hm_ip_long
			//hm_ip_long <- t_hm_ip_long
		}
	}
}

// Reads from wjobs populated originally by readNetflow and writes them disk and *.gz files to the specified config.Outpath.
func writeWorker(routineID int,passive bool, finished chan bool, wjobs <-chan []string,OutPath string){
	var fout F
	firsttime := true
	justcount := 0
	last_filename := ""
	for true{
		for j := range wjobs {
			tobewritten, ts := j[0],j[1]
			//fmt.Println(tobewritten)
			justcount ++
	                if justcount % 10000 == 0 {
				print("+")
			}
			//continue //FATAL TODO: remove this
	                if firsttime || justcount >= 2000000{
				if len(last_filename) > 0 {
					CloseGZ(fout)
					os.Rename(last_filename + ".notready",last_filename)
				}
				last_filename = fmt.Sprintf("%s/@%s_worker%d.tsv.lesscols.gz", OutPath, ts , routineID)
				fout = CreateGZ(last_filename + ".notready")
				firsttime = false
				justcount = 0
			}
	                WriteGZ(fout, tobewritten)
		}
		if passive {break}
	}
	CloseGZ(fout)
	finished <- true

}

func readNetflow(passive bool, finished chan bool, ipdb []DnsDB, cnamedb []DnsDB, parser string, OutPath string, inpath string, is_gz bool, ljobs chan<- []string, conf Configuration) { //rt *iptree.IPTree
	f, err := os.Open(inpath)
        if err != nil {
		fmt.Println(err)
		return
        }
        defer f.Close()
	var r *bufio.Reader
	if is_gz {
		gz, _ := gzip.NewReader(f)
		r = bufio.NewReaderSize(gz, 8*1024)
	} else {
		r = bufio.NewReaderSize(f, 8*1024)
	}
	for true {
		for line, isPrefix, err := r.ReadLine();err == nil;line, isPrefix, err = r.ReadLine() {
			s := string(line)
			if isPrefix {print("Netflowread: Buffer size overflow for line %v",s)}
			if strings.Contains(s, "TAG,") {continue}
			columns := strings.Split(s, ",")
			if len(columns) != conf.NumCols {continue}
			if len(columns[conf.SrcipIndex]) < 3 {continue}
			//lbl := label(columns[conf.SrcipIndex],conf.NumSplit)
			ljobs <- columns
			//nfLookup(columns, tipdb[lbl], tcdb, parser,wjobs,conf)
		}
		fmt.Println("exited the inner netflow reader loop")
		if passive {break}

	}
	finished <- true
}

func main() {
	// Read the arguments, first argument should always be tthe config file, e.g. go-conf.json
	argswithprog := os.Args
	//go newCpuStats()
	filename := fmt.Sprintf("correlation-%d.log",time.Now().Unix())
	file,err := os.OpenFile(filename,os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	log.SetOutput(file)

	var OutPath string
	var dnsinpath,nfinpath []string
	var conf Configuration
	//rtpath := "../routingTable.tsv.gz"
	//rt := populate_rt(rtpath)
	passive := false
	var is_gz bool

	// Reads the config file and initiates a Configuration object.
	if len(argswithprog) > 1 {
		confpath := argswithprog[1]
		fmt.Println(confpath)
		fconf,ferr := ioutil.ReadFile(confpath)
		if ferr !=nil {fmt.Println("err",ferr)}
		err := json.Unmarshal(fconf,&conf)
		if err !=nil {fmt.Println("err",err)}
		fmt.Println(conf)
	}
	// Passive for reading from files. Active for reading from live streams/pipes.
	if passive {
		//is_gz = true
		//dnsinpath = "/live/recording/dns_recording/parser_00/archived/@000000000000001631167260.gz"
		//nfinpath = "/live/recording/netflow_recording/parser_00/archived/@000000000000001631167260.gz"
		is_gz = false
		dnsinpath = []string{"./test/testdns.csv"}
		nfinpath = []string{"./test/testnetflow.csv"}
                OutPath = "/home/amaghsoudlou/correlated/passive"
	} else {
		is_gz = false
		dnsinpath = conf.DNSPipes
		nfinpath = conf.NetflowPipes
		OutPath = conf.OutPath
	}


	dnsfinished := make(chan bool)
	hm_ip := []cmap.ConcurrentMap{}
	hm_ip_backup := []cmap.ConcurrentMap{}
	hm_ip_long := []cmap.ConcurrentMap{}
	hm_ip_long_backup := []cmap.ConcurrentMap{}
	for i := 0; i< conf.NumSplit; i++ {
		hm_ip = append(hm_ip, cmap.New())
		hm_ip_backup = append(hm_ip_backup, cmap.New())
		hm_ip_long = append(hm_ip_long, cmap.New())
		hm_ip_long_backup = append(hm_ip_long_backup, cmap.New())
	}

	hm_cname := cmap.New()
	hm_cname_backup := cmap.New()
	hm_cname_long := cmap.New()
	hm_cname_long_backup := cmap.New()

	ipdb := make([]DnsDB, conf.NumSplit)
	for i := 0; i< conf.NumSplit; i++ {
		last_ts = append(last_ts,0)
		last_ts_long = append(last_ts_long,0)
		ipdb[i] = DnsDB{hm_ip[i], hm_ip_backup[i], hm_ip_long[i],hm_ip_long_backup[i]}
	}
	//ipdb := make(chan []DnsDB,1)
	//ipdb <- tipdb

	//cnamedb := make(chan DnsDB,1)
	cnamedb := make([]DnsDB, 1)
	cnamedb[0] = DnsDB{hm_cname, hm_cname_backup, hm_cname_long,hm_cname_long_backup}
        var finishflags []chan bool
	//var wjobs <-chan []string

	if passive {
		<-dnsfinished
		runtime.GC()
		fillUpQ := make(chan DnsJob, conf.DnsQBufferSize)
		for i := 0; i< conf.NumFillUpWorkers; i++ {
			go fillUpWorker(i,ipdb, cnamedb,fillUpQ,conf)
		}
		go readDNS(passive, dnsfinished, ipdb, cnamedb, dnsinpath[0], is_gz,conf,fillUpQ)
		netflowfinished := make(chan bool)
		writerfinished := make(chan bool)
		wjobs := make(chan []string, conf.WriteQBufferSize)
                go writeWorker(0,passive, writerfinished, wjobs, OutPath) 
		 ljobs := make(chan []string, conf.NetflowQBufferSize)
                go lookUpWorker(ipdb, cnamedb, ljobs, wjobs, conf)
		go readNetflow(passive, netflowfinished, ipdb, cnamedb, "passive" ,OutPath,nfinpath[0],is_gz,wjobs,conf)
                finishflags = append(finishflags, writerfinished)
                finishflags = append(finishflags, netflowfinished)
	} else {
		fillUpQ := make(chan DnsJob, conf.DnsQBufferSize)
		for i := 0; i < conf.NumFillUpWorkers; i++ {
			go fillUpWorker(i,ipdb, cnamedb, fillUpQ,conf)
		}
		for _, dnspipe := range dnsinpath {
                        dnsfinished := make(chan bool)
			go readDNS(passive, dnsfinished, ipdb, cnamedb, dnspipe, is_gz,conf,fillUpQ)
                        finishflags = append(finishflags, dnsfinished)
		}
		writerfinished := make(chan bool)
                ljobs := make([]chan[]string, len(nfinpath))
                wjobs := make([]chan[]string, len(nfinpath))
                for j := 0; j < len(nfinpath); j++ {
                        ljobs[j] = make(chan []string, conf.NetflowQBufferSize)
                        wjobs[j] = make(chan []string, conf.WriteQBufferSize)
                }
                //for i := 0; i < conf.NumWriteWorkers; i++ {
                for i := 0; i < len(nfinpath); i++ {
                        go writeWorker(i, passive, writerfinished, wjobs[i], OutPath)
                }
                finishflags = append(finishflags, writerfinished)

                for i, nfpipe := range nfinpath {
                        netflowfinished := make(chan bool)
                        parser := fmt.Sprintf("%02d",i)
                        go readNetflow(passive, netflowfinished, ipdb, cnamedb, parser,OutPath,nfpipe, is_gz, ljobs[i],conf)
                        for j := 0; j < conf.NumLookUpWorkers; j++ {
                                go lookUpWorker(ipdb, cnamedb, ljobs[i], wjobs[i], conf)
                        }
                        finishflags = append(finishflags, netflowfinished)
                }
	}
	for _,flag := range finishflags {
                <-flag
        }
	if !passive {<-dnsfinished}
	print("DNS process returned!")
}
// Anything after this line is only needed for gzip functions.
type F struct {
        f  *os.File
        gf *gzip.Writer
        fw *bufio.Writer
}

func CreateGZ(s string) (f F) {

        fi, err := os.OpenFile(s, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0660)
        if err != nil {
                log.Printf("Error in Create\n")
                panic(err)
        }
        gf := gzip.NewWriter(fi)
        fw := bufio.NewWriter(gf)
        f = F{fi, gf, fw}
        return
}

func WriteGZ(f F, s string) {
        (f.fw).WriteString(s)
}

func CloseGZ(f F)error {
        err := f.fw.Flush()
        // Close the gzip first.
        f.gf.Close()
        f.f.Close()
        return err
}
