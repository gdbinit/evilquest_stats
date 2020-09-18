//
// Utility to parse EvilQuest samples and gather some stats
//
// reference: https://reverse.put.as/2020/09/17/evilquest-revisited/
//
// (c) Pedro Vilaça 2020, All rights reserved.
// reverser@put.as - https://reverse.put.as
//
// All advertising materials mentioning features or use of this software must display
// the following acknowledgement: This product includes software developed by
// Pedro Vilaca.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list
// of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice, this
// list of conditions and the following disclaimer in the documentation and/or
// other materials provided with the distribution.
// 3. All advertising materials mentioning features or use of this software must
// display the following acknowledgement: This product includes software developed
// by Pedro Vilaca.
// 4. Neither the name of the author nor the names of its contributors may be
// used to endorse or promote products derived from this software without specific
// prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
package main

import (
    "os"
    "io"
    "fmt"
    "flag"
    "sync"
    "path/filepath"
    "debug/macho"
    "syscall"
    "os/signal"
    "github.com/schollz/progressbar/v3"
    "crypto/sha256"
    "encoding/hex"
)

const (
    // the sample has this specific file size so use it to distinguish from
    // everything else if mixed with others
    fileSize = 172792
)

var (
    totalWork int64
    jobGroup sync.WaitGroup
    mainGroup sync.WaitGroup
    codeHashes = make(map[string]int)
    cstringHashes = make(map[string]int)
    mapMutex sync.Mutex
    tasks = make(chan string)
    interrupted bool
)

type todecrypt struct {
    magic int64
    key string
    key_len int64
    encrypted_data []byte
    encrypted_size int64
    end_marker int64
}

func setupCloseHandler() {
    c := make(chan os.Signal)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    go func() {
        <- c
        fmt.Println("\r - Ctrl+C pressed!")
        interrupted = true
        jobGroup.Wait()
        showResults()
        os.Exit(0)
    }()
}

func get_sha256(buf []byte) string {
    hash := sha256.New()
    hash.Write(buf)
    bs := hash.Sum(nil)
    hash_string := hex.EncodeToString(bs)
    return hash_string
}

func analyseBinary(path string) {
    r, err := os.Open(path)
    if err != nil {
        fmt.Printf("[-] ERROR: %s @ %s\n", err.Error(), path)
        return
    }

    defer r.Close()
    machoFile, err := macho.NewFile(r)
    // maybe fat
    if err != nil {
        return
    } 
    defer machoFile.Close()
    sec := machoFile.Section("__text")
    if sec != nil {
        b := make([]byte, sec.Size)
        r := sec.Open()
        if _, err := r.Read(b); err != nil {
            return
        }
        hash := get_sha256(b)
        // maps are not thread safe
        mapMutex.Lock()
        codeHashes[hash]++
        mapMutex.Unlock()
    }

    sec = machoFile.Section("__cstring")
    if sec != nil {
        b := make([]byte, sec.Size)
        r := sec.Open()
        if _, err := r.Read(b); err != nil {
            return
        }
        hash := get_sha256(b)
        // maps are not thread safe
        mapMutex.Lock()
        cstringHashes[hash]++
        mapMutex.Unlock()
        // fmt.Printf("%s -> %s\n", path, hash)
    }

}

func analyseFolder(input_folder string, jobs int) {
    var err error

    // find out the total amount of work
    fmt.Printf("[+] Counting number of files to analyse...")
    err = filepath.Walk(input_folder, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return nil
        }
        if info.Mode().IsRegular() && info.Size() == fileSize {
            totalWork++
        }
        return nil
    })
    if err != nil {
        fmt.Printf("[-] Error: walking through target folder: %s\n", err.Error())
    }

    bar := progressbar.Default(totalWork)
    
    if jobs > 1 {
        jobGroup.Add(jobs)
        for i := 0; i < jobs; i++ {
            go func(worker int) {
                defer jobGroup.Done()
                for {
                    path, ok := <- tasks
                    if !ok {
                        return
                    }
                    analyseBinary(path)
                    bar.Add(1)
                }
            }(i)
        }
    } 

    err = filepath.Walk(input_folder, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return nil
        }
        if interrupted == true {
            return io.EOF
        }

        if info.Mode().IsRegular() && info.Size() == fileSize {
                if jobs > 1 {
                    tasks <- path
                } else {
                    analyseBinary(path)
                    bar.Add(1)
                }
        }
        return nil
    })
    
    // the walk was stopped, the signal handler will wait for any jobs still running
    // since mainGroup.Done() isn't executed, the main thread will block when we exit this function
    // otherwise we would have a race since the signal handler is executing in a go routine
    if err == io.EOF {
        // "Always close a channel on the producer side"
        close(tasks)
        return
    }
    if err != nil {
        fmt.Printf("[-] Error: walking through target folder: %s\n", err.Error())
    }    

    if jobs > 1 {
        // no more tasks
        close(tasks)
        // wait for go routines with work to finish
        jobGroup.Wait()
    }
    showResults()
    // we are done so main thread can resume execution after this
    // we don't defer because if interrupted we don't want main thread to resume
    mainGroup.Done()
}

func showResults() {
    fmt.Println("__text map")
    for k, v := range codeHashes {
        fmt.Println(k,v)    
    }

    fmt.Println("__cstring map")
    for k, v := range cstringHashes {
        fmt.Println(k,v)    
    }
}

func main() {
    // setup handler for SIGTERM
    setupCloseHandler()

    fmt.Printf("EvilQuest/ThiefQuest Mach-O Stats\n")
    fmt.Printf("(c) 2020 Pedro Vilaca. All Rights Reserved\n\n")

    var input string
    var jobs int

    flag.StringVar(&input, "i", "", "file or folder to analyse")
    flag.IntVar(&jobs, "n", 1, "number of parallel scanners to run (default 1)")
    flag.Parse()

    if input == "" {
        fmt.Printf("[-] ERROR: please set a file or folder to analyse\n")
        fmt.Println("Usage:")
        flag.PrintDefaults()
        os.Exit(1)              
    }

    // the main thread does nothing, just waits for the main job because of possible
    // race condition with the signal handler
    mainGroup.Add(1)
    go analyseFolder(input, jobs)
    mainGroup.Wait()
}
