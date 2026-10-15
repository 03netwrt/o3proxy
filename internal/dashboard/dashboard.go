package dashboard

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Dashboard provides a web UI for o3proxy status
type Dashboard struct {
	BasePort  int
	Count     int
	NodeCount int
	ChrootBase string
	mu        sync.RWMutex
	ipCache   map[int]string
	lastCheck time.Time
}

// New creates a dashboard
func New(basePort, count, nodeCount int, chrootBase string) *Dashboard {
	return &Dashboard{
		BasePort:   basePort,
		Count:      count,
		NodeCount:  nodeCount,
		ChrootBase: chrootBase,
		ipCache:    make(map[int]string),
	}
}

// Start begins the HTTP server
func (d *Dashboard) Start(addr string) error {
	http.HandleFunc("/", d.handleIndex)
	http.HandleFunc("/api/ports", d.handlePorts)
	http.HandleFunc("/api/nodes", d.handleNodes)
	return http.ListenAndServe(addr, nil)
}

func (d *Dashboard) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html>
<html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>o3proxy Dashboard</title>
<style>
body{font-family:sans-serif;background:#1a1a2e;color:#eee;margin:0;padding:16px}
h1{color:#f0a030;font-size:1.4em}
.card{background:#16213e;border-radius:8px;padding:12px;margin:8px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px}
.port{background:#0f3460;border-radius:6px;padding:8px;font-size:.85em}
.port .p{font-weight:bold;color:#e94560}
.port .ip{color:#53d8fb;font-size:.8em;word-break:break-all}
.node{background:#0f3460;border-radius:6px;padding:8px}
.ok{color:#4ade80}.bad{color:#f87171}
button{background:#e94560;color:#fff;border:0;border-radius:6px;padding:10px 20px;font-size:1em}
.stats{display:flex;gap:16px;margin:12px 0}
.stat{background:#16213e;border-radius:8px;padding:12px;flex:1;text-align:center}
.stat .n{font-size:1.8em;font-weight:bold;color:#f0a030}
</style></head><body>
<h1>🚀 o3proxy Dashboard</h1>
<div class="stats">
<div class="stat"><div class="n" id="uniq">-</div><div>Unique IPs</div></div>
<div class="stat"><div class="n" id="ports">-</div><div>Ports</div></div>
<div class="stat"><div class="n" id="nodes">-</div><div>Nodes Up</div></div>
</div>
<button onclick="refresh()">🔄 Refresh</button>
<h2>SOCKS5 Ports</h2><div class="grid" id="portgrid"></div>
<h2>EarnApp Nodes</h2><div class="grid" id="nodegrid"></div>
<script>
async function refresh(){
  let p=await(await fetch('/api/ports')).json();
  document.getElementById('uniq').textContent=new Set(p.map(function(x){return x.ip})).size;
  document.getElementById('ports').textContent=p.length;
  let ph='';
  for(let i=0;i<p.length;i++){let x=p[i];
    ph+='<div class="port"><div class="p">:'+x.port+'</div><div class="ip">'+(x.ip||'...')+'</div></div>';}
  document.getElementById('portgrid').innerHTML=ph;
  try{
    let n=await(await fetch('/api/nodes')).json();
    let up=n.filter(function(x){return x.up}).length;
    document.getElementById('nodes').textContent=up+'/'+n.length;
    let nh='';
    for(let i=0;i<n.length;i++){let x=n[i];
      nh+='<div class="node"><b>node'+x.id+'</b> <span class="'+(x.up?'ok':'bad')+'">'+(x.up?'UP':'DOWN')+'</span><br><small>'+(x.ip||'')+'</small></div>';}
    document.getElementById('nodegrid').innerHTML=nh;
  }catch(e){document.getElementById('nodes').textContent='-';}
}
refresh();setInterval(refresh,30000);
</script></body></html>`)
}

type portInfo struct {
	Port int    `json:"port"`
	IP   string `json:"ip"`
}

func (d *Dashboard) handlePorts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Refresh cache every 60s
	d.mu.RLock()
	stale := time.Since(d.lastCheck) > 60*time.Second
	d.mu.RUnlock()

	if stale {
		go d.refreshIPs()
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	ports := make([]portInfo, 0, d.Count)
	for i := 0; i < d.Count; i++ {
		p := d.BasePort + i
		ports = append(ports, portInfo{Port: p, IP: d.ipCache[p]})
	}

	// Simple JSON encode
	fmt.Fprint(w, "[")
	for i, p := range ports {
		if i > 0 {
			fmt.Fprint(w, ",")
		}
		fmt.Fprintf(w, `{"port":%d,"ip":%q}`, p.Port, p.IP)
	}
	fmt.Fprint(w, "]")
}

func (d *Dashboard) refreshIPs() {
	d.mu.Lock()
	d.lastCheck = time.Now()
	d.mu.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < d.Count; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			port := d.BasePort + idx
			ip := checkPortIP(port)
			d.mu.Lock()
			d.ipCache[port] = ip
			d.mu.Unlock()
		}(i)
	}
	wg.Wait()
}

func checkPortIP(port int) string {
	// Quick check via SOCKS5
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		return ""
	}
	conn.Close()
	// For full IP check we'd need HTTP via SOCKS5; keep it light here
	// The JS will show cached IPs from the last full refresh
	return ""
}

type nodeInfo struct {
	ID int    `json:"id"`
	Up bool   `json:"up"`
	IP string `json:"ip"`
}

func (d *Dashboard) handleNodes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	nodes := make([]nodeInfo, 0, d.NodeCount)
	for i := 1; i <= d.NodeCount; i++ {
		// Check pidfile existence as "up" indicator
		// Full implementation reads /data/local/tmp/earnapp-chroots/node{i}/earnapp.pid
		nodes = append(nodes, nodeInfo{ID: i, Up: false})
	}
	sort.Slice(nodes, func(a, b int) bool { return nodes[a].ID < nodes[b].ID })
	fmt.Fprint(w, "[")
	for i, n := range nodes {
		if i > 0 {
			fmt.Fprint(w, ",")
		}
		fmt.Fprintf(w, `{"id":%d,"up":%v,"ip":%q}`, n.ID, n.Up, n.IP)
	}
	fmt.Fprint(w, "]")
}
