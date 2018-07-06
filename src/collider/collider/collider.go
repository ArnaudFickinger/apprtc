// Copyright (c) 2014 The WebRTC project authors. All Rights Reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Package collider implements a signaling server based on WebSocket.
package collider

import (
	"crypto/tls"
	"golang.org/x/net/websocket"
	"encoding/json"
	"errors"
	//"html"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
	//"fmt"
	"math/rand"
)

const registerTimeoutSec = 10

// This is a temporary solution to avoid holding a zombie connection forever, by
// setting a 1 day timeout on reading from the WebSocket connection.
const wsReadTimeoutSec = 60 * 60 * 24

type Collider struct {
	*roomTable
	dash *dashboard
}

type Response_t struct{
	Result string  `json:"result"`
	Params Params_t `json:"params"`
}

type Params_t struct{
	Room_id string `json:"room_id"`
	Client_id string `json:"client_id"`
	Wss_url string `json:"wss_url"`
	Wss_post_url string `json:"wss_post_url"`
	Is_initiator bool `json:"is_initiator"`
	Pc_config Pc_config_t `json:"pc_config"`
	Messages []string `json:"messages, omitempty"`
}



type Pc_config_t struct{
	IceServers []IceServer_t `json:"iceServers"`
}

type IceServer_t struct{
	Urls string `json:"urls"`
	Credential string `json:"credential, omitempty"`
	Username string `json:"username, omitempty"`
}




func NewCollider(rs string) *Collider {
	return &Collider{
		roomTable: newRoomTable(time.Second*registerTimeoutSec, rs),
		dash:      newDashboard(),
	}
}

// Run starts the collider server and blocks the thread until the program exits.
func (c *Collider) Run(p int, useTls bool) {
	http.Handle("/ws", websocket.Handler(c.wsHandler))
	http.HandleFunc("/status", c.httpStatusHandler)
	http.HandleFunc("/", c.httpHandler)

	var e error

	pstr := ":" + strconv.Itoa(p)
	if useTls {
		config := &tls.Config {
			// Only allow ciphers that support forward secrecy for iOS9 compatibility:
			// https://developer.apple.com/library/prerelease/ios/technotes/App-Transport-Security-Technote/
			CipherSuites: []uint16 {
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			},
			PreferServerCipherSuites: true,
		}
		server := &http.Server{ Addr: pstr, Handler: nil, TLSConfig: config }

		e = server.ListenAndServeTLS("/cert/cert.pem", "/cert/key.pem")
	} else {
		e = http.ListenAndServe(pstr, nil)
	}

	if e != nil {
		log.Fatal("Run: " + e.Error())
	}
}

// httpStatusHandler is a HTTP handler that handles GET requests to get the
// status of collider.
func (c *Collider) httpStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Access-Control-Allow-Origin", "*")
	w.Header().Add("Access-Control-Allow-Methods", "GET")

	rp := c.dash.getReport(c.roomTable)
	enc := json.NewEncoder(w)
	if err := enc.Encode(rp); err != nil {
		err = errors.New("Failed to encode to JSON: err=" + err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		c.dash.onHttpErr(err)
	}
}

// httpHandler is a HTTP handler that handles GET/POST/DELETE requests.
// POST request to path "/$ROOMID/$CLIENTID" is used to send a message to the other client of the room.
// $CLIENTID is the source client ID.
// The request must have a form value "msg", which is the message to send.
// DELETE request to path "/$ROOMID/$CLIENTID" is used to delete all records of a client, including the queued message from the client.
// "OK" is returned if the request is valid.
func (c *Collider) httpHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Access-Control-Allow-Origin", "*")
	w.Header().Add("Access-Control-Allow-Methods", "POST, DELETE")

	p := strings.Split(r.URL.Path, "/")
	if len(p) != 3 {
		//c.httpError("Invalid path: "+html.EscapeString(r.URL.Path), w)
		//return
	}
	action, rid := p[1], p[2]

    log.Print(rid)

    cid := ""


	switch action {
        case "join":

            initiator:=true
            //todo: if room non empty initiator false
            if len(c.roomTable.room(rid).clients) == 1 {
                log.Print("not initiator")
		        initiator = false
	        }



            cidi := 0
            for true{
                cidi = 10000000 + rand.Intn(90000000)
                /*if err = c.roomTable.register(rid, cid, w); err != nil {
                    continue
                }*/ //TODO
                break
            }


            cid = strconv.Itoa(cidi)
                //c.dash.incrWs()

               // defer c.roomTable.deregister(rid, cid)
            log.Print("JOIN from " + cid)
            stun1 := IceServer_t{"turn:leia.tureex.com:5349?transport=udp", "USERNAME", "CREDENTIAL"}
            stun2 := IceServer_t{"turn:leia.tureex.com:5349?transport=tcp", "USERNAME", "CREDENTIAL"}
            //TODO: add omitempty
            turn := IceServer_t{Urls:"stun:leia.tureex.com:5349"}

            servers := []IceServer_t{stun1, stun2, turn}

            pc_config_ := Pc_config_t{servers}
            var params Params_t

            if initiator == false {
            keys := make([]string, len(c.roomTable.room(rid).clients))
            i := 0
            for k := range c.roomTable.room(rid).clients {
                keys[i] = k
                i++
            }
            params = Params_t{rid,cid, "wss://leia2.tureex.com:443/ws", "https://leia2.tureex.com:443", initiator, pc_config_, c.roomTable.room(rid).clients[keys[0]].msgs} //todo:replace true
            } else{
            params = Params_t{Room_id: rid,Client_id: cid, Wss_url: "wss://leia2.tureex.com:443/ws",Wss_post_url: "https://leia2.tureex.com:443", Is_initiator: initiator, Pc_config: pc_config_} //todo:write label
            }



            response := Response_t{"SUCCESS", params}
            b, _ := json.Marshal(response)
            io.WriteString(w, string(b))
		    c.roomTable.room(rid)
		    c.roomTable.rooms[rid].client(cid)
            return
        case "message":



            cid = p[3]
            log.Print("MESSAGE from " + cid)
            body, err := ioutil.ReadAll(r.Body)
            if err != nil {
                c.httpError("Failed to read request body: "+err.Error(), w)
                return
            }
            m := string(body)
            log.Print("m = " + m)
            /*if m == "" {
                log.Print("emptyyy")
                c.httpError("Empty request body", w)
                return
            }*/
            if err := c.roomTable.send(rid, cid, m); err != nil {
                c.httpError("Failed to send the message: "+err.Error(), w)
                return
            }
            return

        case "leave":


            cid = p[3]
            log.Print("LEAVE from " + cid)
            c.roomTable.remove(rid, cid)


                //c.dash.incrWs()

            //c.roomTable.deregister(rid, cid)
            return

	}

	switch r.Method {

	case "POST": //todo

        rid = p[1]
        cid = p[2]
        log.Print("POST from " + cid)
        log.Print(r.URL.Path)

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			c.httpError("Failed to read request body: "+err.Error(), w)
			return
		}
		m := string(body)
		log.Print("m= "+m)
		/*if m == "" {
			log.Print("emptyyy")
			//c.httpError("Empty request body", w)
			//return
		}*/
		if err := c.roomTable.send(rid, cid, m); err != nil {
			c.httpError("Failed to send the message: "+err.Error(), w)
			return
		}
		return
	case "DELETE":
	    rid = p[1]
        cid = p[2]
	    log.Print("DELETE from " + cid)
		c.roomTable.remove(rid, cid)
		return
	default:
		return
	}
    //log.Print(string(b))

}

// wsHandler is a WebSocket server that handles requests from the WebSocket client in the form of:
// 1. { 'cmd': 'register', 'roomid': $ROOM, 'clientid': $CLIENT' },
// which binds the WebSocket client to a client ID and room ID.
// A client should send this message only once right after the connection is open.
// or
// 2. { 'cmd': 'send', 'msg': $MSG }, which sends the message to the other client of the room.
// It should be sent to the server only after 'regiser' has been sent.
// The message may be cached by the server if the other client has not joined.
//
// Unexpected messages will cause the WebSocket connection to be closed.
func (c *Collider) wsHandler(ws *websocket.Conn) {
	var rid, cid string

	registered := false

	var msg wsClientMsg
loop:
	for {
		err := ws.SetReadDeadline(time.Now().Add(time.Duration(wsReadTimeoutSec) * time.Second))
		if err != nil {
			c.wsError("ws.SetReadDeadline error: "+err.Error(), ws)
			break
		}

		err = websocket.JSON.Receive(ws, &msg)
		if err != nil {
			if err.Error() != "EOF" {
				c.wsError("websocket.JSON.Receive error: "+err.Error(), ws)
			}
			break
		}

		switch msg.Cmd {
		case "register":
		    log.Print("register")
			if registered {
				c.wsError("Duplicated register request", ws)
				break loop
			}
			if msg.RoomID == "" || msg.ClientID == "" {
				c.wsError("Invalid register request: missing 'clientid' or 'roomid'", ws)
				break loop
			}
			if err = c.roomTable.register(msg.RoomID, msg.ClientID, ws); err != nil {
				c.wsError(err.Error(), ws)
				break loop
			}
			registered, rid, cid = true, msg.RoomID, msg.ClientID
			c.dash.incrWs()

			defer c.roomTable.deregister(rid, cid)
			break
		case "send":
		    log.Print("send")
			if !registered {
			    log.Print("client not regist")
				c.wsError("Client not registered", ws)
				break loop
			}
			log.Print("send m " + msg.Msg)
			if msg.Msg == "" {

				c.wsError("Invalid send request: missing 'msg'", ws)
				break loop
			}

			c.roomTable.send(rid, cid, msg.Msg)
			break
		default:
			c.wsError("Invalid message: unexpected 'cmd'", ws)
			break
		}
	}
	// This should be unnecessary but just be safe.
	ws.Close()
}

func (c *Collider) httpError(msg string, w http.ResponseWriter) {
	err := errors.New(msg)
	http.Error(w, err.Error(), http.StatusInternalServerError)
	c.dash.onHttpErr(err)
}

func (c *Collider) wsError(msg string, ws *websocket.Conn) {
	err := errors.New(msg)
	sendServerErr(ws, msg)
	c.dash.onWsErr(err)
}
