package main

import (
    "fmt"
    "os"
    "os/exec"
    "bufio"
    "bytes"
    "path/filepath"
)

func main(){
    var fileName string
    if len(os.Args) < 2 {
        return
    } else {
        fileName = os.Args[1]
    }

    var fp *os.File
    var err error 

    fp, err = os.Open(fileName)
    if err != nil {
        panic(err)
    }
    defer fp.Close()

    reader := bufio.NewReader(fp)

    // 0x0000 - 0x003F
    // 先頭2バイトのマジックナンバー'MZ'と
    // 0x003C - 0x003Fに書かれたPEヘッダ開始アドレスを得る
    var mzheader [0x40]byte
    for i := 0; err == nil && i < len(mzheader); i++ {
        mzheader[i], err = reader.ReadByte()
    }
    if string(mzheader[:2]) != "MZ" {
        fmt.Fprintln(os.Stderr,"file is not EXE")
        return
    }
    peheader_pos := mzheader[60]       + 
                    mzheader[61] <<  8 +
                    mzheader[62] << 16 +
                    mzheader[63] << 24

    // PEヘッダ開始位置まで読み飛ばす
    for i := 0; err == nil && i < int(peheader_pos - 0x40); i++ {
        reader.ReadByte()
    }

    var peheader [6]byte
    for i := 0; err == nil && i < len(peheader); i++ {
        peheader[i], err = reader.ReadByte()
    }
    // 先頭が'PE\0\0'か確認
    if !bytes.Equal(peheader[:4], []byte{0x50, 0x45, 0x00, 0x00}) {
        fmt.Fprintln(os.Stderr,"file is not EXE")
        return
    }

    var cmd_path string
    // 'PE\0\0'の後ろに続く2バイトで32bit/64bitを判定
    if bytes.Equal(peheader[4:6], []byte{0x4C, 0x01}) {
        cmd_path = "x86/depends.exe"
    } else if bytes.Equal(peheader[4:6], []byte{0x64, 0x86}) {
        cmd_path = "x64/depends.exe"
    } else {
        fmt.Fprintln(os.Stderr,"Unknown PE")
        return
    }

    cmd := exec.Command(cmd_path, fileName)
    cmd.Dir = filepath.Dir(os.Args[0])
    err = cmd.Start()
    if err != nil {
        panic(err)
    }
}

