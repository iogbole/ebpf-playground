package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const CLOCKS_PER_SEC = float64(100)

var (
	cpuCorePrefix = regexp.MustCompile(`cpu\d+`)
)

type CpuStat struct {
	TotalUsage   CPUUsage `json:"totalUsage"`
	LogicalCores int      `json:"logicalCores"`
}

type CPUUsage struct {
	User      float64 `json:"user"`
	Nice      float64 `json:"nice"`
	System    float64 `json:"system"`
	Idle      float64 `json:"idle"`
	IoWait    float64 `json:"ioWait"`
	Irq       float64 `json:"irq"`
	SoftIrq   float64 `json:"softIrq"`
	Steal     float64 `json:"steal"`
	Guest     float64 `json:"guest"`
	GuestNice float64 `json:"guestNice"`
}

func main() {
	collectPerMinute := 30 // Change this to adjust the number of times per minute

	ticker := time.NewTicker(time.Minute / time.Duration(collectPerMinute))
	defer ticker.Stop()

	for range ticker.C {
		stat, err := cpuStat("/proc")
		if err != nil {
			fmt.Println("Error:", err)
			continue
		}
		totalUsage := stat.TotalUsage.User + stat.TotalUsage.System
		totalUsagePercent := (totalUsage / (totalUsage + stat.TotalUsage.Idle)) * 100
		cpuUsage := struct {
			TotalUsagePercent float64  `json:"totalUsagePercent"`
			TotalUsage        CPUUsage `json:"totalUsage"`
		}{
			totalUsagePercent,
			stat.TotalUsage,
		}
		cpuUsageJSON, err := json.Marshal(cpuUsage)
		if err != nil {
			fmt.Println("Error:", err)
			continue
		}
		fmt.Println(string(cpuUsageJSON))
	}
}

func cpuStat(procRoot string) (CpuStat, error) {
	stat := CpuStat{}
	data, err := ioutil.ReadFile(path.Join(procRoot, "stat"))
	if err != nil {
		return stat, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "cpu ") {
			parts := strings.Fields(line)
			if stat.TotalUsage.User, err = strconv.ParseFloat(parts[1], 64); err != nil {
				return stat, err
			}
			if stat.TotalUsage.Nice, err = strconv.ParseFloat(parts[2], 64); err != nil {
				return stat, err
			}
			if stat.TotalUsage.System, err = strconv.ParseFloat(parts[3], 64); err != nil {
				return stat, err
			}
			if stat.TotalUsage.Idle, err = strconv.ParseFloat(parts[4], 64); err != nil {
				return stat, err
			}
			if stat.TotalUsage.IoWait, err = strconv.ParseFloat(parts[5], 64); err != nil {
				return stat, err
			}
			if stat.TotalUsage.Irq, err = strconv.ParseFloat(parts[6], 64); err != nil {
				return stat, err
			}
			if stat.TotalUsage.SoftIrq, err = strconv.ParseFloat(parts[7], 64); err != nil {
				return stat, err
			}
			if stat.TotalUsage.Steal, err = strconv.ParseFloat(parts[8], 64); err != nil {
				return stat, err
			}
		} else if cpuCorePrefix.MatchString(line) {
			stat.LogicalCores++
		}
	}
	stat.TotalUsage.User /= CLOCKS_PER_SEC
	stat.TotalUsage.Nice /= CLOCKS_PER_SEC
	stat.TotalUsage.System /= CLOCKS_PER_SEC
	stat.TotalUsage.Idle /= CLOCKS_PER_SEC
	stat.TotalUsage.IoWait /= CLOCKS_PER_SEC
	stat.TotalUsage.Irq /= CLOCKS_PER_SEC
	stat.TotalUsage.SoftIrq /= CLOCKS_PER_SEC
	stat.TotalUsage.Steal /= CLOCKS_PER_SEC
	return stat, nil
}
