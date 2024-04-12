package main

import (
	"context"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"log"
	"net/http"
)

//var (
////	nonceStore         = openid.NewSimpleNonceStore()
////	discoveryCache     = openid.NewSimpleDiscoveryCache()
////	store              = sessions.NewCookieStore([]byte("something-very-secret"))
////	defaultSessionName = "ghs-session"
//)

type UserOAuth struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

//
//type UserInfo struct {
//	Id       string `json:"id"`
//	Email    string `json:"email"`
//	Name     string `json:"name"`
//	NickName string `json:"nickName"`
//}
//
//type M map[string]interface{}

func init() {
	gob.Register(&UserInfo{})
	gob.Register(&M{})
}

func getUserInfo(provider string, token *oauth2.Token) (*UserOAuth, error) {
	var endpoint string
	switch provider {
	case "github":
		endpoint = "https://api.github.com/user"
	case "microsoft":
		endpoint = "https://graph.microsoft.com/v1.0/me"
	}

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var user UserOAuth
	if err = json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}
	return &user, nil
}

func handleOpenId(provider string, oauthConfig *oauth2.Config) {

	http.HandleFunc("/-/login", func(w http.ResponseWriter, r *http.Request) {
		//构造登录认证页面的URL
		http.Redirect(w, r, oauthConfig.AuthCodeURL("state"), http.StatusFound)
	})

	http.HandleFunc("/-/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		token, err := oauthConfig.Exchange(context.Background(), code)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fmt.Println(provider, "access token:", token)

		user, err := getUserInfo(provider, token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		session, err := store.Get(r, defaultSessionName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		userInfo := &UserInfo{
			Id:       user.Email,
			Email:    user.Email,
			Name:     user.Email,
			NickName: user.Email,
		}
		session.Values["user"] = userInfo
		if err = session.Save(r, w); err != nil {
			log.Println("session save error:", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Println("user login", user.Name, user.Email)

		nextUrl := r.FormValue("next")
		if nextUrl == "" {
			nextUrl = "/"
		}
		http.Redirect(w, r, nextUrl, http.StatusFound)
	})

	//http.HandleFunc("/-/user", func(w http.ResponseWriter, r *http.Request) {
	//	session, err := store.Get(r, defaultSessionName)
	//	if err != nil {
	//		http.Error(w, err.Error(), http.StatusInternalServerError)
	//		return
	//	}
	//	val := session.Values["user"]
	//	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	//	data, _ := json.Marshal(val)
	//	w.Write(data)
	//})

	//http.HandleFunc("/-/logout", func(w http.ResponseWriter, r *http.Request) {
	//	session, err := store.Get(r, defaultSessionName)
	//	if err != nil {
	//		http.Error(w, err.Error(), http.StatusInternalServerError)
	//		return
	//	}
	//	delete(session.Values, "user")
	//	session.Options.MaxAge = -1
	//	nextUrl := r.FormValue("next")
	//	_ = session.Save(r, w)
	//	if nextUrl == "" {
	//		nextUrl = r.Referer()
	//	}
	//	http.Redirect(w, r, nextUrl, 302)
	//})
}

func handleOAuthLogin(provider string, oauthConfig *oauth2.Config, hsServer *HTTPStaticServer) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		//本地认证
		//username := r.URL.Query().Get("username")
		//password := r.URL.Query().Get("password")
		username := r.FormValue("username")
		password := r.FormValue("password")
		if username != "" && password != "" {
			users := hsServer.readUserConf()
			for _, user := range users.User {
				value := user[username]
				if password == value {
					session, err := store.Get(r, defaultSessionName)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					userInfo := &UserInfo{
						Id:       username,
						Email:    username,
						Name:     username,
						NickName: username,
					}
					session.Values["user"] = userInfo
					if err = session.Save(r, w); err != nil {
						log.Println("session save error:", err)
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					log.Println(username, "login")

					nextUrl := r.FormValue("next")
					if nextUrl == "" {
						nextUrl = "/"
					}
					http.Redirect(w, r, nextUrl, http.StatusFound)
					return
				}
			}
		} else {
			//第三方认证 构造登录认证页面的URL
			http.Redirect(w, r, oauthConfig.AuthCodeURL("state"), http.StatusFound)
		}
	}
}

func handleOAuthCallback(provider string, oauthConfig *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		token, err := oauthConfig.Exchange(context.Background(), code)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fmt.Println(provider, "access token:", token)

		user, err := getUserInfo(provider, token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		session, err := store.Get(r, defaultSessionName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		userInfo := &UserInfo{
			Id:       user.Email,
			Email:    user.Email,
			Name:     user.Email,
			NickName: user.Email,
		}
		session.Values["user"] = userInfo
		if err = session.Save(r, w); err != nil {
			log.Println("session save error:", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Println(user.Name, user.Email, "login")

		nextUrl := r.FormValue("next")
		if nextUrl == "" {
			nextUrl = "/"
		}
		http.Redirect(w, r, nextUrl, http.StatusFound)
	}
}

func handleSysInfo() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		data, _ := json.Marshal(map[string]interface{}{
			"version": VERSION,
		})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
		w.Write(data)
	}
}
