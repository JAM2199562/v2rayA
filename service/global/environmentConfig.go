package global

import (
	"fmt"
	"github.com/stevenroose/gonfig"
	"log"
	"os"
	"sync"
)

type Params struct {
	Address       string `id:"address" short:"a" default:"0.0.0.0:2017" desc:"监听地址"`
	Config        string `id:"config" short:"c" default:"/etc/v2ray/v2raya.json" desc:"V2RayA配置文件路径"`
	Mode          string `id:"mode" short:"m" desc:"可选systemctl, service, docker, universal. 不设置则自动检测"`
	SSRListenPort int    `short:"s" default:"12346" desc:"使用ss或ssr时的ssr server监听端口"`
	PassCheckRoot bool   `desc:"可跳过启动时的权限检查"`
	ResetPassword bool   `id:"reset-password"`
	ShowVersion   bool   `id:"version"`
}

var params Params

func initFunc() {
	err := gonfig.Load(&params, gonfig.Conf{
		FileDisable:       true,
		FlagIgnoreUnknown: false,
		EnvPrefix:         "V2RAYA_",
	})
	if err != nil {
		if err.Error() != "unexpected word while parsing flags: '-test.v'" {
			log.Fatal(err)
		}
	}
	if params.ShowVersion {
		fmt.Println(Version)
		os.Exit(0)
	}
}

var once sync.Once

func GetEnvironmentConfig() *Params {
	once.Do(initFunc)
	return &params
}
