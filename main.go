// Static project main.go
package main

import (
	//"bytes"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

/*定义cdr话单文件结构体*/
type CdrFile struct {
	CdrHead
	CdrData
}

/*定义cdr话单文件头结构体*/
type CdrHead struct {
	File_length                                  uint   /*文件总长度*/
	Header_length                                uint   /*头长度*/
	High_Release_Identifier                      string /*High_Release_Identifier*/
	High_Version_Identifier                      string /*High_Version_Identifier*/
	Low_Release_Identifier                       string /*Low_Release_Identifier*/
	Low_Version_Identifier                       string /*Low_Version_Identifier*/
	File_opening_timestamp                       uint   /*文件打开时间戳*/
	Timestamp_when_last_CDR_was_appended_to_file uint   /*最后一个cdr添加到文件的时间戳*/
	Number_of_CDRs_in_file                       uint   /*cdr个数*/
	File_sequence_number                         uint   /*文件序列号*/
	File_Closure_Trigger_Reason                  uint   /*文件关闭的原因*/
	IP_Address_of_Node_that_generated_file       []byte /*生成话单的节点地址*/
	Lost_CDR_indicator                           uint   /*丢失话单指示*/
	Length_of_CDR_routeing_filter                uint   /*cdr路由过滤的长度*/
}

/*定义话单文件话单部分结构体*/
type CdrData struct {
	System_type        uint     /*业务类型*/
	Record_type        uint     /*记录类型*/
	Source_addr        []string /*数据源*/
	Sequence           uint     /*序列号*/
	File_name          string   /*原始话单文件名*/
	CauseForRecClosing uint     /*话单关闭原因*/
	Create_date        []string /*话单生成时间*/
	Imsi_number        string   /*用户imsi*/
	Start_datetime     []string /*用户上线时间*/
	End_datetime       []string /*用户下线时间*/
	Duaration          uint     /*时长*/
	Data_up            uint     /*上行流量*/
	Data_down          uint     /*下行流量*/
	Cell_id            string   /*小区id*/
	Local_up           uint     /*本地上行流量*/
	Local_down         uint     /*本地下行流量*/
}

/*定义cdr流量统计信息结构体*/
type CdrStatic struct {
	//Imsi_number string /*用户imsi*/
	//Cell_id     string /*小区id*/
	Duaration  uint /*时长*/
	Data_up    uint /*上行流量*/
	Data_down  uint /*下行流量*/
	Local_up   uint /*本地上行流量*/
	Local_down uint /*本地下行流量*/
}

/*16进制转换成10进制*/
func computer(b []byte, n int) uint {
	tmp := uint(0)
	nn := uint(8 * (n - 1))
	for i := 0; i < n; i++ {
		tmp += uint(b[i]) << nn
		nn = nn - 8
	}
	return tmp
}

/*计算话单offset*/
func offset_cdr(f *os.File, cdrindex int) int {
	if cdrindex == 0 {
		return 50
	} else {
		cdroffset := offset_cdr(f, cdrindex-1)
		f.Seek(int64(cdroffset), 0)
		buffer := make([]byte, 2)
		f.Read(buffer)
		cdrlen := int(buffer[0]*16+buffer[1]*1) + 4
		return cdrlen + cdroffset
	}

}

/*话单文件头解析*/
func (cdrhead *CdrHead) Parse(f *os.File) CdrHead {
	/*文件读取位置归零*/
	f.Seek(0, 0)

	/*计算文件总长度*/
	buffer := make([]byte, 4)
	f.Read(buffer)
	cdrhead.File_length = computer(buffer, 4)
	//fmt.Println(cdrhead.File_length)

	/*计算文件头长度*/
	f.Seek(0, os.SEEK_CUR)
	f.Read(buffer)
	cdrhead.Header_length = computer(buffer, 4)
	//fmt.Println(cdrhead.Header_length)
	if cdrhead.Header_length != 50 {
		fmt.Println()
		fmt.Println("不能解析此文件，请确认是否为话单文件格式！")
		fmt.Println()
		os.Exit(0)
	}

	/*计算High Release Identifier + High Version Identifier*/
	f.Seek(0, os.SEEK_CUR)
	buffer = make([]byte, 1)
	f.Read(buffer)
	cdrhead.High_Release_Identifier = string(strconv.FormatInt(int64(buffer[0]), 16)[0])
	cdrhead.High_Version_Identifier = string(strconv.FormatInt(int64(buffer[0]), 16)[1])

	/*计算Low Release Identifier + Low Version Identifier*/
	f.Seek(0, os.SEEK_CUR)
	f.Read(buffer)
	cdrhead.Low_Release_Identifier = string(strconv.FormatInt(int64(buffer[0]), 16)[0])
	cdrhead.Low_Version_Identifier = string(strconv.FormatInt(int64(buffer[0]), 16)[1])

	/*计算File opening timestamp*/
	f.Seek(0, os.SEEK_CUR)
	buffer = make([]byte, 4)
	f.Read(buffer)
	cdrhead.File_opening_timestamp = computer(buffer, 4)

	/*计算Timestamp when last CDR was appended to file*/
	f.Seek(0, os.SEEK_CUR)
	f.Read(buffer)
	cdrhead.Timestamp_when_last_CDR_was_appended_to_file = computer(buffer, 4)

	/*计算Number of CDRs in file*/
	f.Seek(0, os.SEEK_CUR)
	f.Read(buffer)
	cdrhead.Number_of_CDRs_in_file = computer(buffer, 4)

	/*计算File sequence number*/
	f.Seek(0, os.SEEK_CUR)
	f.Read(buffer)
	cdrhead.File_sequence_number = computer(buffer, 4)

	/*计算File Closure Trigger Reason*/
	f.Seek(0, os.SEEK_CUR)
	buffer = make([]byte, 1)
	f.Read(buffer)
	cdrhead.File_Closure_Trigger_Reason = computer(buffer, 1)

	/*计算IP Address of Node that generated file*/
	f.Seek(0, os.SEEK_CUR)
	buffer = make([]byte, 20)
	f.Read(buffer)
	cdrhead.IP_Address_of_Node_that_generated_file = buffer

	/*计算Lost CDR indicator*/
	f.Seek(0, os.SEEK_CUR)
	buffer = make([]byte, 1)
	f.Read(buffer)
	cdrhead.Lost_CDR_indicator = computer(buffer, 1)

	/*计算Length of CDR routeing filter*/
	f.Seek(0, os.SEEK_CUR)
	buffer = make([]byte, 2)
	f.Read(buffer)
	cdrhead.Length_of_CDR_routeing_filter = computer(buffer, 1)

	return *cdrhead
}

/*话单文件头打印*/
func (cdrhead CdrHead) Printf() {

}

/*话单文件话单数据解析*/
func (cdrdata *CdrData) Parse(f *os.File, cdrindex int) CdrData {
	/*文件读取位置归零*/
	f.Seek(0, 0)
	offset := offset_cdr(f, cdrindex)
	f.Seek(int64(offset), 0)
	buffer := make([]byte, 2)
	f.Read(buffer)
	cdrdatalen := buffer[0]*16 + buffer[1]*1
	tlvlen := cdrdatalen
	offset = offset + 4
	f.Seek(int64(offset), 0)

	/*循环读取cdr*/
	for tlvlen > 0 {
		buffer = make([]byte, 1)
		f.Read(buffer)
		t := buffer[0]
		offset = offset + 1
		f.Seek(int64(offset), 0)
		buffer = make([]byte, 1)
		f.Read(buffer)
		l := buffer[0]
		offset = offset + 1
		f.Seek(int64(offset), 0)
		switch strconv.FormatInt(int64(t), 16) {
		/*业务类型*/
		case "f9":
			f.Seek(int64(offset), 0)
			buffer = make([]byte, int(l))
			f.Read(buffer)
			cdrdata.System_type = computer(buffer, int(l))
		/*记录类型*/
		case "80":
			f.Seek(int64(offset), 0)
			buffer = make([]byte, int(l))
			f.Read(buffer)
			cdrdata.Record_type = computer(buffer, int(l))
		/*数据源*/
		case "a4":
			f.Seek(int64(offset), 0)
			buffer = make([]byte, int(l))
			f.Read(buffer)
			buffer = buffer[2:]
			_buffer := make([]string, int(l)-2)
			for i, v := range buffer {
				//_buffer[i] = strconv.FormatInt(int64(v), 16)
				_buffer[len(buffer)-i-1] = strconv.FormatInt(int64(v), 10)
			}
			cdrdata.Source_addr = _buffer
		/*序列号*/
		case "91":
			f.Seek(int64(offset), 0)
			buffer = make([]byte, int(l))
			f.Read(buffer)
			cdrdata.Sequence = computer(buffer, int(l))
		/*原始话单文件名*/
		case "90":
			f.Seek(int64(offset), 0)
			buffer = make([]byte, int(l))
			f.Read(buffer)
			cdrdata.File_name = string(buffer)
		/*话单关闭的原因*/
		case "8f":
			f.Seek(int64(offset), 0)
			buffer = make([]byte, int(l))
			f.Read(buffer)
			cdrdata.CauseForRecClosing = computer(buffer, int(l))
		/*话单生成时间*/
		case "8d":
			f.Seek(int64(offset), 0)
			buffer = make([]byte, int(l)-3)
			f.Read(buffer)
			_buffer := make([]string, int(l)-3)
			for i, v := range buffer {
				_buffer[i] = strconv.FormatInt(int64(v), 16)
			}
			cdrdata.Create_date = _buffer
		/*IMSI*/
		case "83":
			f.Seek(int64(offset), 0)
			buffer = make([]byte, int(l))
			f.Read(buffer)
			/*
				for i, v := range buffer {
					_buffer[i] = strconv.FormatInt(int64(v), 16)
					imsi_i := strings.Split(_buffer[i], "")[1]
					buf.WriteString(imsi_i)
				}
			*/
			cdrdata.Imsi_number = string(buffer)
		/*开始时间*/
		case "a6":
			f.Seek(int64(offset), 0)
			buffer = make([]byte, int(l)-3)
			f.Read(buffer)
			_buffer := make([]string, int(l)-3)
			for i, v := range buffer {
				_buffer[i] = strconv.FormatInt(int64(v), 16)
			}
			cdrdata.Start_datetime = _buffer
		/*结束时间*/
		case "a7":
			f.Seek(int64(offset), 0)
			buffer = make([]byte, int(l)-3)
			f.Read(buffer)
			_buffer := make([]string, int(l)-3)
			for i, v := range buffer {
				_buffer[i] = strconv.FormatInt(int64(v), 16)
			}
			cdrdata.End_datetime = _buffer
		/*时长*/
		case "8e":
			f.Seek(int64(offset), 0)
			buffer = make([]byte, int(l))
			f.Read(buffer)
			cdrdata.Duaration = computer(buffer, int(l))
		/*上行流量*/
		case "8c":
			f.Seek(int64(offset), 0)
			buffer = make([]byte, int(l))
			f.Read(buffer)
			cdrdata.Data_up = computer(buffer, int(l))
		/*下行流量*/
		case "82":
			f.Seek(int64(offset), 0)
			buffer = make([]byte, int(l))
			f.Read(buffer)
			cdrdata.Data_down = computer(buffer, int(l))
		/*小区id*/
		case "a0":
			f.Seek(int64(offset), 0)
			buffer = make([]byte, int(l))
			f.Read(buffer)
			cdrdata.Cell_id = string(buffer)
		/*本地上行流量*/
		case "be":
			f.Seek(int64(offset), 0)
			buffer = make([]byte, int(l))
			f.Read(buffer)
			cdrdata.Local_up = computer(buffer, int(l))
		/*本地下行流量*/
		case "bf":
			f.Seek(int64(offset), 0)
			buffer = make([]byte, int(l))
			f.Read(buffer)
			cdrdata.Local_down = computer(buffer, int(l))
		}
		tlvlen = tlvlen - l - 2
		offset = offset + int(l)
		f.Seek(int64(offset), 0)
	}
	return *cdrdata
}

/*话单文件话单数据打印*/
func (cdrdata CdrData) Printf() {
	fmt.Println(strings.Repeat("*", 100))
	if cdrdata.System_type == 3 {
		fmt.Printf("%-50s%+v\n", "system_type:", "宽带业务")
	} else {
		fmt.Printf("%-50s%+v\n", "system_type:", "未知业务")
	}
	if cdrdata.Record_type == 85 {
		fmt.Printf("%-50s%+v\n", "record_type:", "eGW上报")
	} else {
		fmt.Printf("%-50s%+v\n", "record_type:", "未知上报")
	}
	fmt.Printf("%-50s%+v\n", "source_addr:", strings.Join(cdrdata.Source_addr, "."))
	fmt.Printf("%-50s%+v\n", "sequence:", cdrdata.Sequence)
	fmt.Printf("%-50s%+v\n", "file_name:", cdrdata.File_name)
	fmt.Printf("%-50s%+v\n", "causeForRecClosing:", cdrdata.CauseForRecClosing)
	fmt.Printf("%-50s%+v年%+v月%+v日%+v时%+v分%+v秒\n", "create_date:",
		cdrdata.Create_date[0], cdrdata.Create_date[1], cdrdata.Create_date[2],
		cdrdata.Create_date[3], cdrdata.Create_date[4], cdrdata.Create_date[5])
	fmt.Printf("%-50s%+v\n", "imsi_number:", cdrdata.Imsi_number)
	fmt.Printf("%-50s%+v\n", "cell_id:", cdrdata.Cell_id)
	fmt.Printf("%-50s%+v年%+v月%+v日%+v时%+v分%+v秒\n", "start_datetime:",
		cdrdata.Start_datetime[0], cdrdata.Start_datetime[1], cdrdata.Start_datetime[2],
		cdrdata.Start_datetime[3], cdrdata.Start_datetime[4], cdrdata.Start_datetime[5])
	fmt.Printf("%-50s%+v年%+v月%+v日%+v时%+v分%+v秒\n", "end_datetime:",
		cdrdata.End_datetime[0], cdrdata.End_datetime[1], cdrdata.End_datetime[2],
		cdrdata.End_datetime[3], cdrdata.End_datetime[4], cdrdata.End_datetime[5])
	fmt.Printf("%-50s%+v秒\n", "duaration:", cdrdata.Duaration)
	fmt.Printf("%-50s%+v字节\n", "data_up:", cdrdata.Data_up)
	fmt.Printf("%-50s%+v字节\n", "data_down:", cdrdata.Data_down)
	fmt.Printf("%-50s%+v字节\n", "local_up:", cdrdata.Local_up)
	fmt.Printf("%-50s%+v字节\n", "local_down:", cdrdata.Local_down)
	fmt.Println(strings.Repeat("*", 100))
}

/*单个话单文件全部打印*/
func (cdr CdrFile) printf(s string) {
	fold, err := os.Stat(s)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	} else {
		if fold.IsDir() {
			fmt.Println()
			fmt.Println("请输入文件名！")
			fmt.Println()
			os.Exit(0)
		}
	}
	f, err := os.Open(s)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	defer f.Close()
	head := cdr.CdrHead.Parse(f)
	num := int(head.Number_of_CDRs_in_file)

	cdr.CdrData.Parse(f, 0)
	fmt.Println()
	fmt.Println("话单名称：", cdr.File_name)
	fmt.Println("话单数目：", num)
	fmt.Println()
	fmt.Println("num:", 1)
	cdr.CdrData.Printf()
	fmt.Println()
	for i := 1; i < num; i++ {
		fmt.Println("num:", i+1)
		cdr.CdrData.Parse(f, i)
		cdr.CdrData.Printf()
	}
}

/*单个话单文件按条目打印*/
func (cdr CdrFile) printf_num(s string, n int) {
	fold, err := os.Stat(s)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	} else {
		if fold.IsDir() {
			fmt.Println()
			fmt.Println("请输入文件名！")
			fmt.Println()
			os.Exit(0)
		}
	}
	f, err := os.Open(s)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	defer f.Close()
	head := cdr.CdrHead.Parse(f)
	num := int(head.Number_of_CDRs_in_file)
	if n > -1 && n < num {
		cdr.CdrData.Parse(f, n)
		fmt.Println()
		fmt.Println("话单名称：", cdr.File_name)
		fmt.Println("话单数目：", num)
		fmt.Println()
		fmt.Println("num:", n+1)
		cdr.CdrData.Printf()
	} else if n == -1 {
		//fmt.Println("打印完毕")
	} else {
		//fmt.Println(n)
		fmt.Println()
		fmt.Println("请输入正确的话单号！ 1 -", num)
		fmt.Println()
	}

}

/*多个话单文件打印*/
func (cdr CdrFile) printf_n(s []string) {
	for _, v := range s {
		fmt.Println()
		fmt.Println("文件名称：", v)
		cdr.printf(v)
	}
}

/*话单文件打印*/
func (cdr CdrFile) Printf(pstr string) {
	if len(flag.Args()) > 0 {
		//fmt.Println(flag.Args()[0])
		n, err := strconv.Atoi(flag.Args()[0])
		if err != nil {
			s := append(flag.Args(), pstr)
			cdr.printf_n(s)
			//fmt.Println(err)
		}
		cdr.printf_num(pstr, n-1)
	} else {
		cdr.printf(pstr)
	}
}

/*单个话单文件按imsi统计流量*/
func (cdr CdrFile) static_imsi(s string) map[string]CdrStatic {
	fold, err := os.Stat(s)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	} else {
		if fold.IsDir() {
			fmt.Println()
			fmt.Println("请输入文件名！")
			fmt.Println()
			os.Exit(0)
		}
	}
	f, err := os.Open(s)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	defer f.Close()
	head := cdr.CdrHead.Parse(f)
	num := int(head.Number_of_CDRs_in_file)
	static_imsi := make(map[string]CdrStatic)

	for i := 0; i < num; i++ {
		tmp := cdr.CdrData.Parse(f, i)
		t := static_imsi[tmp.Imsi_number]
		if _, exist := static_imsi[tmp.Imsi_number]; exist {
			t.Duaration += tmp.Duaration
			t.Data_up += tmp.Data_up
			t.Data_down += tmp.Data_down
			t.Local_up += tmp.Local_up
			t.Local_down += tmp.Local_down
			static_imsi[tmp.Imsi_number] = t
		} else {
			t.Duaration = tmp.Duaration
			t.Data_up = tmp.Data_up
			t.Data_down = tmp.Data_down
			t.Local_up = tmp.Local_up
			t.Local_down = tmp.Local_down
			static_imsi[tmp.Imsi_number] = t
		}
	}
	return static_imsi
}

/*单个话单文件按cell统计流量*/
func (cdr CdrFile) static_cell(s string) map[string]CdrStatic {
	fold, err := os.Stat(s)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	} else {
		if fold.IsDir() {
			fmt.Println()
			fmt.Println("请输入文件名！")
			fmt.Println()
			os.Exit(0)
		}
	}
	f, err := os.Open(s)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	defer f.Close()
	head := cdr.CdrHead.Parse(f)
	num := int(head.Number_of_CDRs_in_file)
	static_cell := make(map[string]CdrStatic)

	for i := 0; i < num; i++ {
		tmp := cdr.CdrData.Parse(f, i)
		t := static_cell[tmp.Cell_id]
		if _, exist := static_cell[tmp.Cell_id]; exist {
			t.Data_up += tmp.Data_up
			t.Data_down += tmp.Data_down
			t.Local_up += tmp.Local_up
			t.Local_down += tmp.Local_down
			static_cell[tmp.Cell_id] = t
		} else {
			t.Data_up = tmp.Data_up
			t.Data_down = tmp.Data_down
			t.Local_up = tmp.Local_up
			t.Local_down = tmp.Local_down
			static_cell[tmp.Cell_id] = t
		}
	}
	return static_cell
}

/*多个话单文件按imsi统计流量*/
func (cdr CdrFile) static_n_imsi(s []string) map[string]CdrStatic {
	static_n_imsi := cdr.static_imsi(s[0])
	tmp := make(map[string]CdrStatic)
	for i := 1; i < len(s); i++ {
		for k, v := range cdr.static_imsi(s[i]) {
			for kb, vb := range static_n_imsi {
				if kb == k {
					vb.Duaration += v.Duaration
					vb.Data_up += v.Data_up
					vb.Data_down += v.Data_down
					vb.Local_up += v.Local_up
					vb.Local_down += v.Local_down

					static_n_imsi[kb] = vb
					delete(tmp, k)
					break
				} else {
					tmp[k] = v
				}
			}
		}
		for k, v := range tmp {
			static_n_imsi[k] = v
		}
	}
	return static_n_imsi
}

/*多个话单文件按cell统计流量*/
func (cdr CdrFile) static_n_cell(s []string) map[string]CdrStatic {
	static_n_cell := cdr.static_cell(s[0])
	tmp := make(map[string]CdrStatic)
	for i := 1; i < len(s); i++ {
		for k, v := range cdr.static_cell(s[i]) {
			for kb, vb := range static_n_cell {
				if kb == k {
					//vb.Duaration += v.Duaration
					vb.Data_up += v.Data_up
					vb.Data_down += v.Data_down
					vb.Local_up += v.Local_up
					vb.Local_down += v.Local_down

					static_n_cell[kb] = vb
					delete(tmp, k)
					break
				} else {
					tmp[k] = v
					//fmt.Println(tmp)
				}
			}
		}
		for k, v := range tmp {
			static_n_cell[k] = v
			//fmt.Println(k, v)
		}
	}
	return static_n_cell
}

/*话单文件按imsi统计流量打印信息*/
func (cdr CdrFile) Static_imsi_Printf(str string) {
	len := len(flag.Args())
	if len > 0 {
		s := append(flag.Args(), str)
		fmt.Println(strings.Repeat("*", 150))
		fmt.Printf("%-10s%-20s%-15s%-30s%-30s%-30s%-30s\n", "sn", "imsi", "Duaration", "Data_up", "Data_down", "Local_up", "Local_down")
		fmt.Println()
		/*sort排序打印*/
		var keys []string
		m := cdr.static_n_imsi(s)
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var i int = 1
		for _, k := range keys {
			fmt.Printf("%-10d%-20s%-15v%-30v%-30v%-30v%-30v\n", i, k, m[k].Duaration, m[k].Data_up, m[k].Data_down, m[k].Local_up, m[k].Local_down)
			i++
		}
		fmt.Println(strings.Repeat("*", 150))
	} else {
		static_imsi := cdr.static_imsi(str)
		fmt.Println(strings.Repeat("*", 150))
		fmt.Printf("%-10s%-20s%-15s%-30s%-30s%-30s%-30s\n", "sn", "imsi", "Duaration", "Data_up", "Data_down", "Local_up", "Local_down")
		fmt.Println()
		/*sort排序打印*/
		var keys []string
		m := static_imsi
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var i int = 1
		for _, k := range keys {
			fmt.Printf("%-10d%-20s%-15v%-30v%-30v%-30v%-30v\n", i, k, m[k].Duaration, m[k].Data_up, m[k].Data_down, m[k].Local_up, m[k].Local_down)
			i++
		}
		fmt.Println(strings.Repeat("*", 150))
	}
}

/*话单文件按cell统计流量打印信息*/
func (cdr CdrFile) Static_cell_Printf(str string) {
	len := len(flag.Args())
	if len > 0 {
		s := append(flag.Args(), str)
		fmt.Println(strings.Repeat("*", 150))
		fmt.Printf("%-10s%-20s%-30s%-30s%-30s%-30s\n", "sn", "cell", "Data_up", "Data_down", "Local_up", "Local_down")
		fmt.Println()
		/*sort排序打印*/
		var keys []int
		m := cdr.static_n_cell(s)
		for k := range m {
			kk, _ := strconv.Atoi(k)
			keys = append(keys, kk)
		}
		sort.Ints(keys)
		var i int = 1
		for _, k := range keys {
			kk := strconv.FormatInt(int64(k), 10)
			fmt.Printf("%-10d%-20s%-30v%-30v%-30v%-30v\n", i, kk, m[kk].Data_up, m[kk].Data_down, m[kk].Local_up, m[kk].Local_down)
			i++
		}
		fmt.Println(strings.Repeat("*", 150))
	} else {
		static_cell := cdr.static_cell(str)
		fmt.Println(strings.Repeat("*", 150))
		fmt.Printf("%-10s%-20s%-30s%-30s%-30s%-30s\n", "sn", "cell", "Data_up", "Data_down", "Local_up", "Local_down")
		fmt.Println()
		/*sort排序打印*/
		var keys []int
		m := static_cell
		for k := range m {
			kk, _ := strconv.Atoi(k)
			keys = append(keys, kk)
		}
		sort.Ints(keys)
		var i int = 1
		for _, k := range keys {
			kk := strconv.FormatInt(int64(k), 10)
			fmt.Printf("%-10d%-20s%-30v%-30v%-30v%-30v\n", i, kk, m[kk].Data_up, m[kk].Data_down, m[kk].Local_up, m[kk].Local_down)
			i++
		}
		fmt.Println(strings.Repeat("*", 150))
	}
}

/*话单文件打印默认信息*/
func (cdr CdrFile) Init_Printf() {
	fmt.Println(strings.Repeat("*", 150))
	fmt.Println(strings.Repeat("*", 150))
	fmt.Println()
	fmt.Printf("%75s\n", "话单解析工具v1.0.0")
	fmt.Println()
	fmt.Printf("%-20s\n", "使用方法：")
	fmt.Println()

	fmt.Printf("%-80s %-50s\n", "./static -p  test.dat [话单名，如：test.dat]", "打印一个话单")
	fmt.Printf("%-74s %-50s\n", "./static -p  test.dat [话单名，如：test.dat]  1 [系列号，如：1]", "按序列号打印一个话单")
	fmt.Printf("%-81s %-50s\n", "./static -p  test.dat  test1.dat test2.dat ...[多个话单名]", "打印多个话单")
	fmt.Printf("%-78s %-50s\n", "./static -p  *.dat    [匹配话单名，如：*.dat]", "打印匹配的话单")
	fmt.Printf("%-80s %-50s\n", "./static -i  test.dat [话单名，如：test.dat]", "计算一个话单按imsi流量统计")
	fmt.Printf("%-81s %-50s\n", "./static -i  test.dat  test1.dat test2.dat ...[多个话单名]", "计算多个话单按imsi流量统计")
	fmt.Printf("%-78s %-50s\n", "./static -i  *.dat    [匹配话单名，如：*.dat]", "计算匹配话单按imsi流量统计")
	fmt.Printf("%-80s %-50s\n", "./static -c  test.dat [话单名，如：test.dat]", "计算一个话单按cell流量统计")
	fmt.Printf("%-81s %-50s\n", "./static -c  test.dat  test1.dat test2.dat ...[多个话单名]", "计算多个话单按cell流量统计")
	fmt.Printf("%-78s %-50s\n", "./static -c  *.dat    [匹配话单名，如：*.dat]", "计算匹配话单按cell流量统计")
	fmt.Println()
	fmt.Println(strings.Repeat("*", 150))
	fmt.Println(strings.Repeat("*", 150))
}

func main() {

	var p, i, c string
	var cdr CdrFile
	flag.StringVar(&p, "p", "", "printf cdrs")
	flag.StringVar(&i, "i", "", "static cdrs")
	flag.StringVar(&c, "c", "", "static cdrs")
	flag.Parse()
	switch {
	/*p不为空打印话单详情*/
	case p != "":
		cdr.Printf(p)
	/*i不为空，按imsi计算话单流量*/
	case i != "":
		cdr.Static_imsi_Printf(i)
	/*c不为空，按cell计算话单流量*/
	case c != "":
		cdr.Static_cell_Printf(c)
	/*默认打印使用说明*/
	default:
		cdr.Init_Printf()
	}
}
