package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"

	bpf "github.com/iovisor/gobpf/bcc"
)

const (
	MessageMaxBuffer = 8192
)

type TlsMessage struct {
	Ptid    uint64
	Elapsed uint64
	Message [MessageMaxBuffer]byte
}

func readEbpfProgram(filePath string) (string, error) {
	b, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func main() {
	binaryPath := "/lib/x86_64-linux-gnu/libssl.so.3"
	fileName := "tls_tracer_ebpf_program.c"
	eBpfProgramSourceCode, err := readEbpfProgram(fileName)
	if err != nil {
		fmt.Errorf(err.Error())
		os.Exit(1)
	}

	ebpfModule := bpf.NewModule(eBpfProgramSourceCode, []string{})
	defer ebpfModule.Close()

	sslReadEntryUProbe, err := ebpfModule.LoadUprobe("uprobe_entry_SSL_read")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load uprobe_entry_SSL_read: %s\n", err)
		os.Exit(1)
	}

	err = ebpfModule.AttachUprobe(binaryPath, "SSL_read", sslReadEntryUProbe, -1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach SSL_read: %s\n", err)
		os.Exit(1)
	}

	sslReadReturnUProbe, err := ebpfModule.LoadUprobe("uprobe_return_SSL_read")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load uprobe_return_SSL_read: %s\n", err)
		os.Exit(1)
	}

	err = ebpfModule.AttachUprobe(binaryPath, "SSL_read", sslReadReturnUProbe, -1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach SSL_read: %s\n", err)
		os.Exit(1)
	}

	sslWriteEntryUProbe, err := ebpfModule.LoadUprobe("uprobe_entry_SSL_write")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load uprobe_entry_SSL_write: %s\n", err)
		os.Exit(1)
	}

	err = ebpfModule.AttachUprobe(binaryPath, "SSL_write", sslWriteEntryUProbe, -1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach SSL_write: %s\n", err)
		os.Exit(1)
	}

	sslWriteReturnUProbe, err := ebpfModule.LoadUprobe("uprobe_return_SSL_write")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load uprobe_return_SSL_write: %s\n", err)
		os.Exit(1)
	}

	err = ebpfModule.AttachUprobe(binaryPath, "SSL_write", sslWriteReturnUProbe, -1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach SSL_write: %s\n", err)
		os.Exit(1)
	}

	table := bpf.NewTable(ebpfModule.TableId("TLS_DATA_PERF_OUTPUT"), ebpfModule)
	channel := make(chan []byte)
	perfMap, err := bpf.InitPerfMap(table, channel, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		var tlsMessage TlsMessage
		for {
			data := <-channel
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &tlsMessage)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}

			// Finds the index of `\0` to determin end of the string
			cStringTerminationCharacterIndex := bytes.IndexByte(tlsMessage.Message[:], 0)

			// Message may overflow to bigger than our defined `MessageMaxBuffer` buffer, to we cap the index at MessageMaxBuffer.
			if cStringTerminationCharacterIndex == -1 {
				cStringTerminationCharacterIndex = MessageMaxBuffer
			}

			tlsMessageContent := string(tlsMessage.Message[:cStringTerminationCharacterIndex])

			fmt.Println("############### TLS MESSAGE ###########")
			fmt.Println(fmt.Sprintf("Elapsed     -> %d ms", (tlsMessage.Elapsed)))
			fmt.Println(fmt.Sprintf("ptid        -> %d", tlsMessage.Ptid))
			fmt.Println(fmt.Sprintf("Message Size-> %d", cStringTerminationCharacterIndex))
			fmt.Println("tls content:")
			fmt.Printf("%s\n", tlsMessageContent)
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
}
