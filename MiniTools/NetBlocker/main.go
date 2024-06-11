package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

// getConfigFilePath 返回配置文件路径
// 如果文件不存在，则创建一个新的配置文件
func getConfigFilePath() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}

	var configDir string
	switch runtime.GOOS {
	case "windows":
		configDir = filepath.Join(usr.HomeDir, "AppData", "Local", "NetBlocker")
	case "linux":
		configDir = filepath.Join(usr.HomeDir, ".config", "net_blocker")
	case "darwin": // macOS
		configDir = filepath.Join(usr.HomeDir, ".config", "net_blocker")
	default:
		return "", fmt.Errorf("unsupported platform")
	}

	if err := os.MkdirAll(configDir, os.ModePerm); err != nil {
		return "", err
	}

	configFilePath := filepath.Join(configDir, "blocker-config.txt")

	// 检查配置文件是否存在，如果不存在则创建
	if _, err := os.Stat(configFilePath); os.IsNotExist(err) {
		file, err := os.Create(configFilePath)
		if err != nil {
			return "", err
		}
		defer file.Close()

		// 写入示例配置
		_, err = file.WriteString("# 允许网络访问的目录路径，每行一个路径\n" +
			"# [allow] /path/to/allowed_directory1\n" +
			"# [allow] /path/to/allowed_directory2\n\n" +
			"# 不允许网络访问的目录路径，每行一个路径\n" +
			"# [deny] /path/to/blocked_directory1\n" +
			"# [deny] /path/to/blocked_directory2\n")
		if err != nil {
			return "", err
		}

		fmt.Println("-*-*-*-*-*-*-*-*-*-*-")
		fmt.Println("配置文件已创建:", configFilePath)
		fmt.Println("请修改配置文件后再次运行!")
		fmt.Println("-*-*-*-*-*-*-*-*-*-*-")
	}

	return configFilePath, nil
}

// loadConfig 从配置文件加载目录路径
func loadConfig(filename string) (map[string]bool, map[string]bool, error) {
	allowMap := make(map[string]bool)
	denyMap := make(map[string]bool)

	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		switch parts[0] {
		case "[allow]":
			allowPath := strings.Join(parts[1:], " ")
			allowMap[allowPath] = true
			fmt.Println(parts[1])
		case "[deny]":
			denyPath := strings.Join(parts[1:], " ")
			denyMap[denyPath] = true
			fmt.Println(parts[1])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}

	return allowMap, denyMap, nil
}

func main() {
	configPath, err := getConfigFilePath()
	if err != nil {
		fmt.Println("获取配置文件路径时出错:", err)
		return
	}

	allowMap, denyMap, err := loadConfig(configPath)
	if err != nil {
		fmt.Println("加载配置文件时出错:", err)
		return
	}

	for dir := range allowMap {
		fmt.Println("允许网络访问的目录:", dir)
		manageNetworkAccess(dir, true)
	}

	for dir := range denyMap {
		fmt.Println("不允许网络访问的目录:", dir)
		manageNetworkAccess(dir, false)
	}

	fmt.Println("-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-")
	fmt.Println(" 执行完毕，可关闭本窗口！")
	fmt.Println(" 如提示其他错误，请联系支撑！")
	fmt.Println("-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-")

	// 等待用户输入任意字符
	fmt.Scanln()
}

// manageNetworkAccess 管理指定目录下的网络访问
func manageNetworkAccess(dirPath string, allow bool) {
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && isExecutable(path) {
			if allow {
				fmt.Println("允许网络访问的文件路径:", path)
				allowAccess(path)
			} else {
				fmt.Println("阻止网络访问的文件路径:", path)
				blockAccess(path)
			}
		}
		return nil
	})
	if err != nil {
		fmt.Println("遍历目录时出错:", err)
	}
}

// isExecutable 检查文件是否为可执行文件
func isExecutable(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	buff := make([]byte, 512)
	_, err = file.Read(buff)
	if err != nil {
		return false
	}

	// 检查是否为 Windows 可执行文件
	if strings.HasPrefix(string(buff), "MZ") {
		return true
	}

	// 检查是否为 Unix 可执行文件（shebang）
	if strings.HasPrefix(string(buff), "#!") {
		return true
	}

	// 添加更多检查逻辑
	return false
}

// blockAccess 阻止指定文件的网络访问
func blockAccess(executablePath string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name=Block "+filepath.Base(executablePath), "dir=out", "action=block", "program="+executablePath)
	case "linux":
		cmd = exec.Command("sudo", "iptables", "-A", "OUTPUT", "-p", "tcp", "-m", "owner", "--uid-owner", executablePath, "-j", "DROP")
	case "darwin":
		// macOS 示例（您可能需要安装和配置 pfctl 规则来进行阻止）
		cmd = exec.Command("sudo", "pfctl", "-f", "/etc/pf.conf", "-k", executablePath)
	default:
		fmt.Println("不支持的平台")
		return
	}

	err := cmd.Run()
	if err != nil && !strings.Contains(err.Error(), "exit status 1") {
		fmt.Println("阻止网络访问时出错:", executablePath, err)
	}
}

// allowAccess 允许指定文件的网络访问
func allowAccess(executablePath string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		// ruleName := "Block " + filepath.Base(executablePath)
		// exists, status := ruleExists(ruleName)
		// if status != 1 {
		// 	fmt.Printf("Error checking rule existence!!!\n")
		// } else {
		// 	if exists {
		// 		cmd = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=Block "+filepath.Base(executablePath))
		// 	} else {
		// 		fmt.Printf("The rule '%s' does not exist.\n", ruleName)
		// 	}
		// }
		cmd = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=Block "+filepath.Base(executablePath))
	case "linux":
		cmd = exec.Command("sudo", "iptables", "-D", "OUTPUT", "-p", "tcp", "-m", "owner", "--uid-owner", executablePath, "-j", "DROP")
	case "darwin":
		// macOS 示例（您可能需要安装和配置 pfctl 规则来进行允许）
		cmd = exec.Command("sudo", "pfctl", "-f", "/etc/pf.conf", "-k", executablePath)
	default:
		fmt.Println("不支持的平台")
		return
	}
	err := cmd.Run()
	if err != nil && !strings.Contains(err.Error(), "exit status 1") {
		fmt.Println("允许网络访问时出错:", executablePath, err)
	}
}

// ruleExists 检查给定的防火墙规则名称是否存在于Windows防火墙中。
// ruleName: 需要检查的规则名称。
// 返回值:
//
//	bool: 如果规则存在，则返回true；否则返回false。
//	int: 如果执行过程中出现错误，则返回0；否则返回1(已存在)。
func ruleExists(ruleName string) (bool, int) {
	// 使用netsh命令行工具查询指定名称的防火墙规则是否存在。
	cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+ruleName)

	// 使用bytes.Buffer来存储cmd的输出结果。
	var out bytes.Buffer
	// 将cmd的输出重定向到out缓冲区。
	cmd.Stdout = &out

	// 执行cmd命令。
	err := cmd.Run()
	status := 0
	// 如果执行出错，进一步判断是否是因为规则不存在导致的错误。
	if err != nil {
		// 尝试将错误转换为exec.ExitError类型，以获取退出状态码。
		// 如果命令执行出错，可能是由于规则不存在导致的
		if exitError, ok := err.(*exec.ExitError); ok {
			// 如果退出状态码为1，通常表示规则不存在。
			// 检查退出状态码，通常非零值表示错误
			if exitError.ExitCode() == 1 {
				// 返回false，表示规则不存在，且不返回错误。
				status = 1
				return false, status // 规则不存在通常返回错误码1
			}
		}
		// 如果不是规则不存在的特定错误，返回false和原始错误。
		status = 0
		return false, status // 其他错误直接返回
	}

	// 将out缓冲区的内容转换为字符串，以便搜索规则名称。
	output := out.String()
	// 检查输出字符串是否包含规则名称，如果包含，则规则存在。
	return strings.Contains(output, "Rule Name:"+ruleName), status
}
