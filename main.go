package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"github.com/goji/httpauth"
	"golang.org/x/oauth2"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"text/template"

	"github.com/alecthomas/kingpin"
	accesslog "github.com/codeskyblue/go-accesslog"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	//"github.com/go-yaml/yaml"
	"gopkg.in/yaml.v3"
)

type Configure struct {
	Conf            *os.File `yaml:"-"`
	Addr            string   `yaml:"addr"`
	Port            int      `yaml:"port"`
	Root            string   `yaml:"root"`
	Prefix          string   `yaml:"prefix"`
	HTTPAuth        string   `yaml:"httpauth"`
	Cert            string   `yaml:"cert"`
	Key             string   `yaml:"key"`
	Cors            bool     `yaml:"cors"`
	Theme           string   `yaml:"theme"`
	XHeaders        bool     `yaml:"xheaders"`
	Show            bool     `yaml:"show"`
	Upload          bool     `yaml:"upload"`
	Delete          bool     `yaml:"delete"`
	PlistProxy      string   `yaml:"plistproxy"`
	Title           string   `yaml:"title"`
	Debug           bool     `yaml:"debug"`
	GoogleTrackerID string   `yaml:"google-tracker-id"`
	Auth            struct {
		Type     string `yaml:"type"` // openid|http|github
		OpenID   string `yaml:"openid"`
		HTTP     string `yaml:"http"`
		ID       string `yaml:"id"`       // for oauth2
		Secret   string `yaml:"secret"`   // for oauth2
		Redirect string `yaml:"redirect"` // for oauth2
	} `yaml:"auth"`
}

type httpLogger struct{}

func (l httpLogger) Log(record accesslog.LogRecord) {
	log.Printf("%s - %s %d %s", record.Ip, record.Method, record.Status, record.Uri)
}

var (
	defaultPlistProxy = "https://plistproxy.herokuapp.com/plist"
	defaultOpenID     = "https://login.netease.com/openid"
	gcfg              = Configure{}
	logger            = httpLogger{}

	VERSION   = "unknown"
	BUILDTIME = "unknown time"
	GITCOMMIT = "unknown git commit"
	SITE      = "https://github.com/codeskyblue/gohttpserver"
)

func versionMessage() string {
	t := template.Must(template.New("version").Parse(`GoHTTPServer
  Version:        {{.Version}}
  Go version:     {{.GoVersion}}
  OS/Arch:        {{.OSArch}}
  Git commit:     {{.GitCommit}}
  Built:          {{.Built}}
  Site:           {{.Site}}`))
	buf := bytes.NewBuffer(nil)
	t.Execute(buf, map[string]interface{}{
		"Version":   VERSION,
		"GoVersion": runtime.Version(),
		"OSArch":    runtime.GOOS + "/" + runtime.GOARCH,
		"GitCommit": GITCOMMIT,
		"Built":     BUILDTIME,
		"Site":      SITE,
	})
	return buf.String()
}

func parseFlags() error {
	// initial default conf
	gcfg.Root = "./"
	gcfg.Port = 8000
	gcfg.Addr = ""
	gcfg.Theme = "black"
	gcfg.PlistProxy = defaultPlistProxy
	gcfg.Auth.OpenID = defaultOpenID
	gcfg.GoogleTrackerID = "UA-81205425-2"
	gcfg.Title = "HTTP File Server"

	kingpin.HelpFlag.Short('h')
	kingpin.Version(versionMessage())
	kingpin.Flag("conf", "config file path, yaml format").FileVar(&gcfg.Conf)
	kingpin.Flag("root", "root directory, default ./").Short('r').StringVar(&gcfg.Root)
	kingpin.Flag("prefix", "url prefix, eg /foo").StringVar(&gcfg.Prefix)
	kingpin.Flag("port", "listen port, default 8000").IntVar(&gcfg.Port)
	kingpin.Flag("addr", "listen address, eg 127.0.0.1:8000").Short('a').StringVar(&gcfg.Addr)
	kingpin.Flag("cert", "tls cert.pem path").StringVar(&gcfg.Cert)
	kingpin.Flag("key", "tls key.pem path").StringVar(&gcfg.Key)
	kingpin.Flag("auth-type", "Auth type <http|openid>").StringVar(&gcfg.Auth.Type)
	kingpin.Flag("auth-http", "HTTP basic auth (ex: user:pass)").StringVar(&gcfg.Auth.HTTP)
	kingpin.Flag("auth-openid", "OpenID auth identity url").StringVar(&gcfg.Auth.OpenID)
	kingpin.Flag("auth-id", "oauth2 client id").StringVar(&gcfg.Auth.ID)
	kingpin.Flag("auth-secret", "oauth2 client secret").StringVar(&gcfg.Auth.Secret)
	kingpin.Flag("auth-redirect", "oauth2 redirect home page").StringVar(&gcfg.Auth.Redirect)
	kingpin.Flag("theme", "web theme, one of <black|green>").StringVar(&gcfg.Theme)
	kingpin.Flag("show", "enable show support").BoolVar(&gcfg.Show)
	kingpin.Flag("upload", "enable upload support").BoolVar(&gcfg.Upload)
	kingpin.Flag("delete", "enable delete support").BoolVar(&gcfg.Delete)
	kingpin.Flag("xheaders", "used when behind nginx").BoolVar(&gcfg.XHeaders)
	kingpin.Flag("cors", "enable cross-site HTTP request").BoolVar(&gcfg.Cors)
	kingpin.Flag("debug", "enable debug mode").BoolVar(&gcfg.Debug)
	kingpin.Flag("plistproxy", "plist proxy when server is not https").Short('p').StringVar(&gcfg.PlistProxy)
	kingpin.Flag("title", "server title").StringVar(&gcfg.Title)
	kingpin.Flag("google-tracker-id", "set to empty to disable it").StringVar(&gcfg.GoogleTrackerID)
	kingpin.Parse() // first parse conf

	if gcfg.Conf != nil {
		defer func() {
			kingpin.Parse() // command line priority higher than conf
		}()
		ymlData, err := ioutil.ReadAll(gcfg.Conf)
		if err != nil {
			return err
		}
		return yaml.Unmarshal(ymlData, &gcfg)
	}
	return nil
}

func fixPrefix(prefix string) string {
	prefix = regexp.MustCompile(`/*$`).ReplaceAllString(prefix, "")
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	if prefix == "/" {
		prefix = ""
	}
	return prefix
}

type Users struct {
	User []User `yaml:"users"`
}
type User map[string]string

//func myAuthFunc(user, pass string, r *http.Request) bool {
//	return pass == strings.Repeat(user, 3)
//}
func mySimpleBasicAuthFunc(user, pass string, r *http.Request) bool {
	// Equalize lengths of supplied and required credentials by hashing them
	givenUser := sha256.Sum256([]byte(user))
	givenPass := sha256.Sum256([]byte(pass))
	log.Printf("User: %s attemp to login\n", user)

	//cfgFile := filepath.Join(realPath, ".user.yml")
	cfgFile := ".user.yml"
	data, err := ioutil.ReadFile(cfgFile)
	if err != nil {
		//if os.IsNotExist(err) {
		//	return false
		//}
		log.Printf("Err read .user.yml: %v", err)
	}
	users := Users{}
	err = yaml.Unmarshal(data, &users)
	if err != nil {
		log.Printf("Err format .user.yml: %v", err)
	}
	//
	for _, v := range users.User {
		//log.Println("==", k, v)
		for k1, v1 := range v {
			//log.Println("====", k1, v1)
			requiredUser := sha256.Sum256([]byte(k1))
			requiredPass := sha256.Sum256([]byte(v1))
			// Compare the supplied credentials to those set in our options
			if subtle.ConstantTimeCompare(givenUser[:], requiredUser[:]) == 1 &&
				subtle.ConstantTimeCompare(givenPass[:], requiredPass[:]) == 1 {
				return true
			}
		}

	}

	//// Compare the supplied credentials to those set in our options
	//if subtle.ConstantTimeCompare(givenUser[:], requiredUser[:]) == 1 &&
	//	subtle.ConstantTimeCompare(givenPass[:], requiredPass[:]) == 1 {
	//	return true
	//}

	return false
}

func main() {
	if err := parseFlags(); err != nil {
		log.Fatal(err)
	}
	if gcfg.Debug {
		data, _ := yaml.Marshal(gcfg)
		fmt.Printf("--- config ---\n%s\n", string(data))
	}
	log.SetFlags(log.Lshortfile | log.LstdFlags)

	// make sure prefix matches: ^/.*[^/]$
	gcfg.Prefix = fixPrefix(gcfg.Prefix)
	if gcfg.Prefix != "" {
		log.Printf("url prefix: %s", gcfg.Prefix)
	}

	ss := NewHTTPStaticServer(gcfg.Root)
	ss.Prefix = gcfg.Prefix
	ss.Theme = gcfg.Theme
	ss.Title = gcfg.Title
	ss.GoogleTrackerID = gcfg.GoogleTrackerID
	ss.Upload = gcfg.Upload
	ss.Delete = gcfg.Delete
	ss.AuthType = gcfg.Auth.Type

	if gcfg.PlistProxy != "" {
		u, err := url.Parse(gcfg.PlistProxy)
		if err != nil {
			log.Fatal(err)
		}
		u.Scheme = "https"
		ss.PlistProxy = u.String()
	}
	if ss.PlistProxy != "" {
		log.Printf("plistproxy: %s", strconv.Quote(ss.PlistProxy))
	}

	var hdlr http.Handler = ss

	hdlr = accesslog.NewLoggingHandler(hdlr, logger)

	var oauthConfig *oauth2.Config

	// HTTP Basic Authentication
	//userpass := strings.SplitN(gcfg.Auth.HTTP, ":", 2)
	switch gcfg.Auth.Type {
	case "http":
		//if len(userpass) == 2 {
		//	user, pass := userpass[0], userpass[1]
		//	hdlr = httpauth.SimpleBasicAuth(user, pass)(hdlr)
		//}
		opts := httpauth.AuthOptions{
			Realm:    "Restricted",
			AuthFunc: mySimpleBasicAuthFunc,
			//UnauthorizedHandler: myUnauthorizedHandler,
		}
		hdlr = httpauth.BasicAuth(opts)(hdlr)
	case "openid":
		handleOpenID(gcfg.Auth.OpenID, false) // FIXME(ssx): set secure default to false
	case "github":
		oauthConfig = &oauth2.Config{
			ClientID:     gcfg.Auth.ID,
			ClientSecret: gcfg.Auth.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://github.com/login/oauth/authorize",
				TokenURL: "https://github.com/login/oauth/access_token",
			},
			//RedirectURL: fmt.Sprintf("http://localhost:8000%s/-/callback", gcfg.Prefix),
			RedirectURL: fmt.Sprintf("%s%s/-/callback?provider=%s", gcfg.Auth.Redirect, gcfg.Prefix, gcfg.Auth.Type),
			Scopes:      []string{"user:email"},
		}
	case "microsoft":
		oauthConfig = &oauth2.Config{
			ClientID:     gcfg.Auth.ID,
			ClientSecret: gcfg.Auth.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
				TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
			},
			//RedirectURL: fmt.Sprintf("http://localhost:8000%s/-/callback", gcfg.Prefix),
			RedirectURL: fmt.Sprintf("%s%s/-/callback?provider=%s", gcfg.Auth.Redirect, gcfg.Prefix, gcfg.Auth.Type),
			Scopes:      []string{"openid", "profile", "email"},
		}
	case "oauth2-proxy":
		handleOauth2()
	}

	// CORS
	if gcfg.Cors {
		hdlr = handlers.CORS()(hdlr)
	}
	if gcfg.XHeaders {
		hdlr = handlers.ProxyHeaders(hdlr)
	}

	mainRouter := mux.NewRouter()
	router := mainRouter
	if gcfg.Prefix != "" {
		router = mainRouter.PathPrefix(gcfg.Prefix).Subrouter()
		mainRouter.Handle(gcfg.Prefix, hdlr)
		mainRouter.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, gcfg.Prefix, http.StatusTemporaryRedirect)
		})
	}

	router.PathPrefix("/-/assets/").Handler(http.StripPrefix(gcfg.Prefix+"/-/", http.FileServer(Assets)))
	router.HandleFunc("/-/login", handleOAuthLogin(oauthConfig, ss))
	router.HandleFunc("/-/callback", handleOAuthCallback(oauthConfig))
	router.HandleFunc("/-/sysinfo", handleSysInfo(gcfg.Auth.Type))
	router.PathPrefix("/").Handler(hdlr)

	if gcfg.Addr == "" {
		gcfg.Addr = fmt.Sprintf(":%d", gcfg.Port)
	}
	if !strings.Contains(gcfg.Addr, ":") {
		gcfg.Addr = ":" + gcfg.Addr
	}
	_, port, _ := net.SplitHostPort(gcfg.Addr)
	log.Printf("listening on %s, local address http://%s:%s\n", strconv.Quote(gcfg.Addr), getLocalIP(), port)

	srv := &http.Server{
		Handler: mainRouter,
		Addr:    gcfg.Addr,
	}

	var err error
	if gcfg.Key != "" && gcfg.Cert != "" {
		err = srv.ListenAndServeTLS(gcfg.Cert, gcfg.Key)
	} else {
		err = srv.ListenAndServe()
	}
	log.Fatal(err)
}
