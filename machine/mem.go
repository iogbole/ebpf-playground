package main

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"

	"k8s.io/klog/v2"
)

type MemoryStat struct {
	TotalBytes     float64
	FreeBytes      float64
	AvailableBytes float64
	CachedBytes    float64
}

func main() {
	klog.InitFlags(nil)
	defer klog.Flush()

	mem, err := memoryInfo("/proc")
	if err != nil {
		klog.Errorf("Failed to retrieve memory info: %v", err)
		return
	}

	klog.Infof("Total memory: %.2f kB", mem.TotalBytes/1000)
	klog.Infof("Free memory: %.2f kB", mem.FreeBytes/1000)
	klog.Infof("Available memory: %.2f kB", mem.AvailableBytes/1000)
	klog.Infof("Cached memory: %.2f kB", mem.CachedBytes/1000)
}

func memoryInfo(procRoot string) (MemoryStat, error) {
	mem := MemoryStat{}

	data, err := ioutil.ReadFile(filepath.Join(procRoot, "meminfo"))
	if err != nil {
		return mem, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		mul := float64(1)
		if len(parts) == 3 && parts[2] == "kB" {
			mul = 1000
		}
		v, err := strconv.ParseFloat(parts[1], 64)
		if err != nil {
			return mem, fmt.Errorf("broken meminfo line: %s", line)
		}
		switch parts[0] {
		case "MemTotal:":
			mem.TotalBytes = v * mul
		case "MemFree:":
			mem.FreeBytes = v * mul
		case "MemAvailable:":
			mem.AvailableBytes = v * mul
		case "Cached:":
			mem.CachedBytes = v * mul
		}
	}
	return mem, nil
}
