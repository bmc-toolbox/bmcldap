// Copyright © 2018 Joel Rebello <joel.rebello@booking.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/bmc-toolbox/bmcldap/cmd"
)

func main() {

	setupProfiling()
	cmd.Execute()
}

// setup pprof
// log mem, goroutine stats when SIGUSR1 is recieved
func setupProfiling() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	sigDumpStatsChan := make(chan os.Signal, 1)
	signal.Notify(sigDumpStatsChan, syscall.SIGUSR1)
	go func() {
		for {
			_ = <-sigDumpStatsChan
			log.Printf("Goroutines: %d", runtime.NumGoroutine())
			dumpMemUsage()
		}
	}()
}

func dumpMemUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	log.Printf("Alloc = %v MiB", bToMb(m.Alloc))
	log.Printf("\tTotalAlloc = %v MiB", bToMb(m.TotalAlloc))
	log.Printf("\tSys = %v MiB", bToMb(m.Sys))
	log.Printf("\tNumGC = %v\n", m.NumGC)
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}
