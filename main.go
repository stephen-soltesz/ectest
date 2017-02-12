package main

import (
	"crypto/tls"
	"os/exec"
	// "crypto/x509"
	"bytes"
	"encoding/json"
	// "epoxy/nextboot"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"
)

var (
	target = flag.String("url", "", "GET the HTTPS URL.")
	post   = flag.Bool("post", false, "POST the HTTPS URL.")

	nextStage  = flag.Bool("nextstage", false, "Launch the epoxy.nextstage= parameter from /proc/cmdline.")
	endStage   = flag.Bool("endstage", false, "Confirm the epoxy.endstage= parameter from /proc/cmdline.")
	beginStage = flag.Bool("beginstage", false, "Confirm the epoxy.beginstage= parameter from /proc/cmdline.")
	sshKey     = flag.String("public_ssh_host_key", "", "The public ssh host key to publish to ePoxy.")
	// confirm, accept, acknowledge, complete, finish, sync, disable, enable
	// EnableNextstage -- affords connotations of "no-error-observed".
	// CompleteStage -- evokes a sense of "false-positive".
	// TODO support 'walk' operation from stage2.json.
	// TODO support flags for public ssh host key location.
)

/////////////////////////////////////////////////////////////////////////////
type kernelArg struct {
	key   string
	value string
}

// Should preserve order and prevent duplicate keys.
type kernelArgs []kernelArg

// Get performs a simple linear search on the known parameters and returns the first found value.
func (k *kernelArgs) Get(key string) (string, bool) {
	for _, arg := range *k {
		if arg.key == key {
			return arg.value, true
		}
	}
	return "", false
}

func (k *kernelArgs) Add(key string, value string) bool {
	kv := kernelArg{key, value}
	if v, ok := k.Get(key); ok {
		log.Printf("Warning: cannot add duplicate key: %s\n", key)
		log.Printf("Warning: replacing %s with %s\n", v, kv)
		// Original position is lost when replacing the key.
		k.Delete(key)
	}
	*k = append(*k, kv)
	return true
}

func (k *kernelArgs) Delete(key string) bool {
	// Find index.
	for i, arg := range *k {
		if arg.key == key {
			// Recreate list without the i'th element.
			*k = append((*k)[:i], (*k)[i+1:]...)
			return true
		}
	}
	return false
}

func (arg *kernelArg) String() string {
	var param bytes.Buffer
	param.WriteString(arg.key)
	if arg.value != "" {
		param.WriteString("=")
		param.WriteString(arg.value)
	}
	return param.String()
}

type KexecSource struct {
	Vmlinuz   string // Fully qualified URI to vmlinuz image.
	Initramfs string // Fully qualified URI to initramfs image.
	// TODO consider making this a list of strings, for clearer formatting.
	Kargs   string // Additional kernel paramters.
	Command string // Command for kexec. Interpreted as a Go template.
}

type ChainSource struct {
	Source string // Source file.
}

type FallbackSource struct {
	Source  string // Source file.
	Command string // Command to run on source. Interpreted as a Go template.
}

type Nextboot struct {
	Kexec         *KexecSource
	Chain         *ChainSource
	Fallback      *FallbackSource
	Stage2URL     string
	NextStageURL  string
	BeginStageURL string
	EndStageURL   string
	SessionId     string
}

func (n *Nextboot) String() string {
	// Errors only occur for non-UTF8 characters in strings.
	b, _ := json.MarshalIndent(n, "", "    ")
	if b == nil {
		return ""
	}
	return string(b)
}

func Thing() {
	fmt.Println("test")
}

// GetCmdLineFields parses the content of /proc/cmdline and returns the kernelArgs.
func GetCmdLineFields() *kernelArgs {

	data, err := ioutil.ReadFile("/proc/cmdline")
	if err != nil {
		log.Printf("Failed to open /proc/cmdline: %s\n", err)
		return nil
	}

	kargs := &kernelArgs{}

	fields := strings.Fields(string(data))
	for _, f := range fields {
		fmt.Printf("FIELD: %#v\n", f)
		kv := strings.SplitN(f, "=", 2)
		if len(kv) == 2 {
			fmt.Printf("KV: %s == %s\n", kv[0], kv[1])
			kargs.Add(kv[0], kv[1])
		} else {
			fmt.Printf("KV: %s\n", kv[0])
			kargs.Add(kv[0], "")
		}
	}
	return kargs
}

func MakeTmp(name string) *os.File {
	t, err := ioutil.TempFile("", name)
	if err != nil {
		log.Fatal(err)
	}
	return t
}

func Load(input string) (*Nextboot, error) {
	b, err := ioutil.ReadFile(input)
	if err != nil {
		return nil, err
	}
	n := &Nextboot{}
	err = json.Unmarshal(b, n)
	if err != nil {
		return nil, err
	}
	return n, nil
}

func PostDownload(client *http.Client, uri, output string) error {
	// TODO: use a parameter for sshKey not a global.
	v := url.Values{"public_ssh_host_key": []string{*sshKey}}
	resp, err := client.PostForm(uri, v)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Dump response
	f, err := os.Create(output)
	if err != nil {
		return err
	}
	// TODO: retry or resume on error.
	log.Printf("Downloading: %s\n", output)
	l, err := io.Copy(f, resp.Body)
	if l != resp.ContentLength {
		return fmt.Errorf("Expected ContentLength(%d) actually read(%d)", resp.ContentLength, l)
	}
	log.Printf("Wrote: %d bytes\n", l)
	return nil
}

func GetDownload(client *http.Client, uri, output string) error {
	resp, err := client.Get(uri)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Dump response
	f, err := os.Create(output)
	if err != nil {
		return err
	}
	// TODO: retry or resume on error.
	log.Printf("Downloading: %s\n", output)
	l, err := io.Copy(f, resp.Body)
	if l != resp.ContentLength {
		return fmt.Errorf("Expected ContentLength(%d) actually read(%d)", resp.ContentLength, l)
	}
	log.Printf("Wrote: %d bytes\n", l)
	return nil
}

func loadKexec(client *http.Client, kexec *KexecSource, kargs *kernelArgs) error {
	// Download the vmlinuz and initramfs images.
	vmlinuz := MakeTmp("vmlinuz")
	err := GetDownload(client, kexec.Vmlinuz, vmlinuz.Name())
	if err != nil {
		log.Fatal(err)
	}
	// defer os.Remove(vmlinuz.Name())

	// Save local temporary file names for evaluating command template.
	vals := map[string]string{
		"Vmlinuz": vmlinuz.Name(),
	}

	// TODO(soltesz): check for valid secure URI, https://, file://, etc.
	if len(kexec.Initramfs) > 0 {
		initramfs := MakeTmp("initramfs")
		err = GetDownload(client, kexec.Initramfs, initramfs.Name())
		if err != nil {
			log.Fatal(err)
		}
		// defer os.Remove(initramfs.Name())
		vals["Initramfs"] = initramfs.Name()
	}
	if ip, ok := kargs.Get("epoxy.ip"); ok {
		// TODO(soltesz): specify this format for epoxy rather than borrowing the nfs boot IP config.
		// ${net0/ip}::${net0/gateway}:${net0/netmask}:${hostname}:eth0:off:${net0/dns}:8.8.4.4
		fields := strings.SplitN(ip, ":", 9)
		vals["IP"] = fields[0]
		vals["Gateway"] = fields[2]
		vals["Netmask"] = fields[3]
		vals["Hostname"] = fields[4]
		vals["DNS"] = fields[7]
	}
	vals["Kargs"] = evaluateTemplate(vals, kexec.Kargs)

	return forceKexec(vals, kargs)
}

func forceKexec(vals map[string]string, kargs *kernelArgs) error {
	var cmdline bytes.Buffer
	var initrd bytes.Buffer
	var c *exec.Cmd

	// Construct --initrd argument.
	if initramfs, ok := vals["Initramfs"]; ok {
		initrd.WriteString("--initrd=")
		initrd.WriteString(initramfs)
	}

	// Construct --command-line argument.
	cmdline.WriteString("--command-line=")
	if params, ok := vals["Kargs"]; ok {
		cmdline.WriteString(params)
		cmdline.WriteString(" ")
	}
	// kargs := GetCmdLineFields()
	for _, arg := range *kargs {
		cmdline.WriteString(arg.String())
		cmdline.WriteString(" ")
	}

	// ...
	if initrd.Len() > 0 {
		fmt.Printf("/sbin/kexec --force '%s' '%s' '%s'", cmdline.String(), initrd.String(), vals["Vmlinuz"])
		c = exec.Command("/sbin/kexec", "--force", cmdline.String(), initrd.String(), vals["Vmlinuz"])
	} else {
		fmt.Printf("/sbin/kexec --force '%s' '%s'", cmdline.String(), vals["Vmlinuz"])
		c = exec.Command("/sbin/kexec", "--force", cmdline.String(), vals["Vmlinuz"])
	}
	output, err := c.CombinedOutput()
	log.Printf("Error: %s\n", err)
	log.Printf("Output: %s\n", output)
	return err
}

// func executeKexec(vals map[string]string, command string) error {
// 	// TODO(soltesz): construct kexec command.
// 	// /sbin/kexec --force --reuse-cmdline --append='{{.Kargs}}' --initrd={{.Initramfs}} {{.Vmlinuz}}
// 	cmd := evaluateTemplate(vals, command)
// 	log.Printf("# %s\n", cmd)
//
// 	// TODO(soltesz): make this better.
// 	c := exec.Command("/bin/sh", "-c", cmd)
//
// 	// This should not return, but if it does, we want to log all output.
// 	output, err := c.CombinedOutput()
// 	log.Printf("Error: %s\n", err)
// 	log.Printf("Output: %s\n", output)
// 	return err
// }

func loadFallback(client *http.Client, f *FallbackSource) error {
	fallback := MakeTmp("fallback")
	err := GetDownload(client, f.Source, fallback.Name())
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(fallback.Name())

	vals := map[string]string{
		"Source": fallback.Name(),
	}

	cmd := evaluateTemplate(vals, f.Command)
	c := exec.Command("/bin/sh", "-c", cmd)

	output, err := c.CombinedOutput()
	log.Printf("Error: %s\n", err)
	log.Printf("Output: %s\n", output)
	return err
}

func evaluateTemplate(vals map[string]string, t string) string {

	// Parse command as a template.
	tmpl, err := template.New("template").Parse(t)
	if err != nil {
		log.Fatal(err)
	}
	var b bytes.Buffer
	err = tmpl.Execute(&b, vals)
	if err != nil {
		log.Fatal(err)
	}
	return string(b.Bytes())
}

func processURI(client *http.Client, uri string, post bool, kargs *kernelArgs) error {
	// Get and parse the nextboot configuration.
	var err error
	// TODO: make the temp name reflect the flag, e.g. nextstage, beginstage, endstage, etc.
	ntmp := MakeTmp("nextboot")
	log.Printf("Downloading %s -> %s\n", uri, ntmp.Name())
	if post {
		err = PostDownload(client, uri, ntmp.Name())
	} else {
		err = GetDownload(client, uri, ntmp.Name())
	}
	if err != nil {
		log.Fatal(err)
	}
	// defer os.Remove(nextboot.Name())

	// Load the configuration.
	n, err := Load(ntmp.Name())
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%s\n", n.String())
	if n.SessionId != "" {
		kargs.Add("epoxy.sessionid", n.SessionId)
		// TODO: is this the right location for this action?
		kargs.Delete("epoxy.nextstage")
	}
	if n.EndStageURL != "" {
		kargs.Add("epoxy.endstage", n.EndStageURL)
	}

	if n.Kexec != nil {
		err = loadKexec(client, n.Kexec, kargs)
	} else if n.Chain != nil {
		err = processURI(client, n.Chain.Source, false, kargs)
	} else if n.Fallback != nil {
		err = loadFallback(client, n.Fallback)
	} else {
		err = nil
	}
	return err
}

func main() {
	flag.Parse()
	// TODO: we may want to bake-in the epoxy certificate or provide a flag.
	// certPool, err := x509.SystemCertPool()
	// if err != nil {
	//     log.Fatal(err)
	// }
	kargs := GetCmdLineFields()
	for _, arg := range *kargs {
		fmt.Printf("%s\n", arg.String())
	}
	server, ok := kargs.Get("epoxy.server")
	if !ok {
		server = "Unknown epoxy server"
	}

	if *beginStage {
		fmt.Println("TODO: run epoxy.beginstage URL")
		url, ok := kargs.Get("epoxy.beginstage")
		if ok {
			*target = url
		}
	} else if *endStage {
		fmt.Println("TODO: run epoxy.endstage URL")
		url, ok := kargs.Get("epoxy.endstage")
		if ok {
			*target = url
		}
	} else if *nextStage {
		fmt.Println("TODO: run epoxy.nextstage URL")
		// TODO: should we remove the nextstage key from the kargs list?
		url, ok := kargs.Get("epoxy.nextstage")
		if ok {
			*target = url
		}

	}
	if *target == "" {
		os.Exit(0)
	}
	// Use POST if the url references the epoxy server; otherwise, use GET.
	*post = strings.Contains(*target, server)

	// Setup HTTPS client.
	tlsConfig := &tls.Config{
		// RootCAs:      certPool,
		MinVersion: tls.VersionTLS10,
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	err := processURI(client, *target, *post, kargs)
	if err != nil {
		log.Fatal(err)
	}
	os.Exit(1)
}
