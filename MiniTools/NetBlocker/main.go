package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

// getConfigFilePath returns the configuration file path based on the OS
func getConfigFilePath() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}

	var configDir string
	switch runtime.GOOS {
	case "windows":
		configDir = filepath.Join(usr.HomeDir, "AppData", "Local", "Blocker")
	case "linux":
		configDir = filepath.Join(usr.HomeDir, ".config", "blocker")
	case "darwin": // macOS
		configDir = filepath.Join(usr.HomeDir, ".config", "blocker")
	default:
		return "", fmt.Errorf("unsupported platform")
	}

	if err := os.MkdirAll(configDir, os.ModePerm); err != nil {
		return "", err
	}

	configFilePath := filepath.Join(configDir, "blocker-config.txt")
	// Check if the config file exists, if not, create it
	if _, err := os.Stat(configFilePath); os.IsNotExist(err) {
		file, err := os.Create(configFilePath)
		if err != nil {
			return "", err
		}
		defer file.Close()

		// Write an example configuration
		_, err = file.WriteString("# Add your directories here, one per line\n#添加要屏蔽的程序主路径，一行一个，可以屏蔽目录下所有可执行文件。")
		if err != nil {
			return "", err
		}
		fmt.Println("Configuration file created at:", configFilePath)
	}

	return configFilePath, nil
}

// loadConfig loads the configuration file with each line being a directory path
func loadConfig(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var directories []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			directories = append(directories, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return directories, nil
}

func main() {
	configPath, err := getConfigFilePath()
	if err != nil {
		fmt.Println("Error getting configuration file path:", err)
		return
	}

	directories, err := loadConfig(configPath)
	if err != nil {
		fmt.Println("Error loading configuration:", err)
		return
	}

	for _, dir := range directories {
		fmt.Println("Processing directory:", dir)
		blockNetworkAccess(dir)
	}
}

// blockNetworkAccess blocks network access for all executables in the given directory
func blockNetworkAccess(dirPath string) {
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && isExecutable(path) {
			fmt.Println("Blocking network access for:", path)
			blockAccess(path)
		}
		return nil
	})
	if err != nil {
		fmt.Println("Error walking through directory:", err)
	}
}

// isExecutable checks if the file is an executable
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

	// Check if it's a Windows executable
	if strings.HasPrefix(string(buff), "MZ") {
		return true
	}

	// Check if it's a Unix executable (shebang)
	if strings.HasPrefix(string(buff), "#!") {
		return true
	}

	// Add more checks as needed
	return false
}

// blockAccess blocks network access for a specific executable
func blockAccess(executablePath string) {
	// Replace the following command with the appropriate command to block network access on your OS
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name=Block "+executablePath, "dir=out", "action=block", "program="+executablePath)
	case "linux":
		cmd = exec.Command("sudo", "iptables", "-A", "OUTPUT", "-p", "tcp", "-m", "owner", "--uid-owner", executablePath, "-j", "DROP")
	case "darwin":
		// MacOS example (You might need to install and configure pfctl rules for blocking)
		cmd = exec.Command("sudo", "pfctl", "-f", "/etc/pf.conf", "-k", executablePath)
	default:
		fmt.Println("Unsupported platform")
		return
	}

	err := cmd.Run()
	if err != nil {
		fmt.Println("Failed to block network access for:", executablePath, err)
	}
}
