package main

import (
	"fmt"
	"os"

	"keygen/vmprotect"
	"time"
)

/*
$exported_algorithm = "RSA";
$exported_bits = 2048;
$exported_private = "SHqphqqk10w3aJDHhIMkAj/FYY5R1cr6X/fQn7fVKcdVxgd+DpMrtmYi4zeOlQGB0x5Rj9JBftC65cmPUO98gSCQiqwhV9BL1P39cw4vORAA0MH+0EMTQJC/Nqfoi1iw1x4mojOCemFAqHckO2u2hksg/fcf1p/OhL/LI2ZkjsBEb502L4Okr+30rXtDWaHKdoN+Ey/wM8woN5RHmVkx44HW+aCqfGu+sDJw/juvWETV3WblEV07HBXwfvQu19L85JIeTM27+TVd57lzdhKdyuel156KHYu8lGbRLDQW4XE+G+RwhEeCN0SA70qiy1yFOUwwUCsZ2ytpyZshJFmHaQ==";
$exported_modulus = "tZy2ayOS55H48Nwv7wjN6OsPbcRs63aeunCfz4kHMLL+tinVe4E2K9kOoF4jGsVAf3pOJa5m9Wbqe0+secmnEvMqOhZgBI696mMEir+R0jSAJj01byOw/UTp7DNRxRHnWjlQoCZB4/INgSDnVJhvSZJPlea+3BXHfZwky1PF/Tcg7XIiLQEQguaIShoxsOAo6wTmQ1bfXx2DyBc9La2SBqMj5+C4uU6958N81MUkVixRpiLTfMdZBxJu215NslLuQI82FyoD8T+57l9UvdEwsq24Bw9IeNbe781J0eFVJgcaNBiOaon18Xb1jzgLCdMLU5lyzACjdPX5Fb2j5Uvhzw==";
$exported_product_code = "XgdTzLalxNk=";
*/

func main() {
	vmpConfig, err := vmprotect.NewConfig("RSA", 2048, "SHqphqqk10w3aJDHhIMkAj/FYY5R1cr6X/fQn7fVKcdVxgd+DpMrtmYi4zeOlQGB0x5Rj9JBftC65cmPUO98gSCQiqwhV9BL1P39cw4vORAA0MH+0EMTQJC/Nqfoi1iw1x4mojOCemFAqHckO2u2hksg/fcf1p/OhL/LI2ZkjsBEb502L4Okr+30rXtDWaHKdoN+Ey/wM8woN5RHmVkx44HW+aCqfGu+sDJw/juvWETV3WblEV07HBXwfvQu19L85JIeTM27+TVd57lzdhKdyuel156KHYu8lGbRLDQW4XE+G+RwhEeCN0SA70qiy1yFOUwwUCsZ2ytpyZshJFmHaQ==",
		"tZy2ayOS55H48Nwv7wjN6OsPbcRs63aeunCfz4kHMLL+tinVe4E2K9kOoF4jGsVAf3pOJa5m9Wbqe0+secmnEvMqOhZgBI696mMEir+R0jSAJj01byOw/UTp7DNRxRHnWjlQoCZB4/INgSDnVJhvSZJPlea+3BXHfZwky1PF/Tcg7XIiLQEQguaIShoxsOAo6wTmQ1bfXx2DyBc9La2SBqMj5+C4uU6958N81MUkVixRpiLTfMdZBxJu215NslLuQI82FyoD8T+57l9UvdEwsq24Bw9IeNbe781J0eFVJgcaNBiOaon18Xb1jzgLCdMLU5lyzACjdPX5Fb2j5Uvhzw==",
		"XgdTzLalxNk=")
	if err != nil {
		fmt.Printf("初始化问题: %s\n", err.Error())

		exit("初始化失败", 1)
	}

	fmt.Print("初始化成功\n")

	license := vmprotect.License{
		Name:"testUser",
		Email:"admin@qq.com",
		Expiration:time.Date(2017, 10, 19, 0,0,0,0, time.UTC),
		HardwareId:[]byte{0,1,2,3},
		RunningTimeLimit:200,
		UserData:[]byte("UserData, length <= 255"),
		Version: 1,
	}

	key, err := license.Generate(*vmpConfig)

	if err != nil {
		fmt.Printf("生成vmpKey失败: %s\n", err.Error())
	} else {
		fmt.Print(key + "\n")
	}

	deLicense, err := vmprotect.ParseLicense(key, "AAEAAQ==", vmpConfig.Modules, vmpConfig.ProductCode, vmpConfig.Bits)

	if err != nil {
		fmt.Print("转换Key失败: ", err.Error(), "\n")
	} else {
		fmt.Print(deLicense.Name, "\n")
		fmt.Print(deLicense.Email, "\n")
		fmt.Print(string(deLicense.UserData), "\n")
		fmt.Print(deLicense.Expiration, "\n")
		fmt.Print(deLicense.HardwareId, "\n")
	}
}

func exit(message string, code int) {
	fmt.Printf("正在退出进程, 原因: %s\n", message)
	os.Exit(code)
}