let graphData = null;

async function loadAnalysis(){
  try {
    const res = await fetch('/api/analysis');
    const data = await res.json();
    if(data.graph){
      graphData = data.graph;
      renderGraph(graphData);
      renderAnomalies(data.anomalies || []);
      renderEvents(data.recent_events || []);
      renderAttackSummary(data);
      renderTimeline(data.timeline || []);
      updateStats();
    } else if(data.error){
      console.error('Analysis error', data.error);
    }
  } catch(e){ console.error(e); }
}

async function reloadAnalysis(){
  await fetch('/api/reload', {method:'POST'});
  await loadAnalysis();
}

function updateStats(){
  if(!graphData) return;
  const hosts = graphData.nodes.filter(n=>n.type==='host').length;
  const alerts = graphData.nodes.filter(n=>n.type==='alert').length;
  const edges = graphData.edges.length;
  document.getElementById('stats').textContent = `Hosts: ${hosts} | Alerts: ${alerts} | Edges: ${edges}`;
}

function renderAnomalies(anoms){
  const el = document.getElementById('anomalies');
  el.innerHTML = anoms.map(a=>`<li><strong>${a.entity_id}</strong>: score ${a.score.toFixed(2)} – ${a.reason}</li>`).join('') || '<li>No anomalies</li>';
}

function renderEvents(events){
  const el = document.getElementById('events');
  el.innerHTML = events.map(e=>`<li>${e.timestamp} <span class="bad">[P${e.priority||''}]</span> ${e.src_ip||''}:${e.src_port||''} -> ${e.dst_ip||''}:${e.dst_port||''} <em>${e.signature}</em></li>`).join('');
}

function renderAttackSummary(data){
  const el = document.getElementById('attack-summary');
  if(!el) return;
  if(!data.most_aggressive_attacker){
    el.textContent = 'No attacker data.';
    return;
  }
  el.innerHTML = `<strong>Most Aggressive Attacker:</strong> ${data.most_aggressive_attacker} (${data.most_aggressive_attacker_count} events)<br/>`+
                 `<strong>Most Attacked Defender:</strong> ${data.most_attacked_defender||'N/A'} (${data.most_attacked_defender_count||0} events)`;
}

function renderTimeline(entries){
  const el = document.getElementById('timeline');
  if(!el) return;
  el.innerHTML = entries.map(t=>`<li><strong>${t.src_ip||'?'} -> ${t.dst_ip||'?'}:</strong> ${t.signature} <span style="color:#999">(${t.count} evts ${t.start} – ${t.end})</span></li>`).join('');
}

// D3 force-directed graph
let simulation, svg, linkGroup, nodeGroup;
function initGraph(){
  if(typeof d3 === 'undefined'){
    const g = document.getElementById('graph');
    g.innerHTML = '<div style="padding:20px;color:#f87171;">D3 library failed to load. Check network connectivity or bundle a local copy.</div>';
    console.error('D3 not loaded');
    return;
  }
  svg = d3.select('#graph').append('svg').attr('width','100%').attr('height','100%');
  linkGroup = svg.append('g').attr('class','links');
  nodeGroup = svg.append('g').attr('class','nodes');
  simulation = d3.forceSimulation()
    .force('link', d3.forceLink().id(d=>d.id).distance(d=> d.type==='alert'?120:60))
    .force('charge', d3.forceManyBody().strength(-250))
    .force('center', d3.forceCenter(window.innerWidth/2, document.getElementById('graph').clientHeight/2));
  window.addEventListener('resize', ()=>{
    simulation.force('center', d3.forceCenter(window.innerWidth/2, document.getElementById('graph').clientHeight/2));
  });
}

function renderGraph(g){
  if(!svg) initGraph();
  const links = linkGroup.selectAll('line').data(g.edges, d=>d.source+"->"+d.target);
  links.exit().remove();
  const linksEnter = links.enter().append('line')
    .attr('class', d=> 'edge '+ (d.alerts.length? 'alert':'') )
    .attr('stroke-width', d=> Math.min(8, 1 + Math.log(d.count+1)));
  links.merge(linksEnter);

  const nodes = nodeGroup.selectAll('g').data(g.nodes, d=>d.id);
  nodes.exit().remove();
  const nodesEnter = nodes.enter().append('g').attr('class', d=> 'node-'+d.type).call(d3.drag()
    .on('start', dragstarted)
    .on('drag', dragged)
    .on('end', dragended));
  nodesEnter.append('circle')
    .attr('r', d=> d.type==='alert'? 10: 6)
    .attr('fill', d=> d.type==='alert'? '#f59e0b':'#3b82f6')
    .append('title').text(d=>d.label);
  nodesEnter.append('text')
    .attr('x', 12)
    .attr('dy','0.35em')
    .style('font-size','10px')
    .text(d=> d.label.slice(0,18));
  nodes.merge(nodesEnter);

  simulation.nodes(g.nodes).on('tick', ticked);
  simulation.force('link').links(g.edges);
  simulation.alpha(0.8).restart();

  function ticked(){
    linkGroup.selectAll('line')
      .attr('x1', d=> d.source.x)
      .attr('y1', d=> d.source.y)
      .attr('x2', d=> d.target.x)
      .attr('y2', d=> d.target.y);
    nodeGroup.selectAll('g')
      .attr('transform', d=>`translate(${d.x},${d.y})`);
  }
}

function dragstarted(event, d){
  if(!event.active) simulation.alphaTarget(0.3).restart();
  d.fx = d.x; d.fy = d.y;
}
function dragged(event, d){ d.fx = event.x; d.fy = event.y; }
function dragended(event, d){ if(!event.active) simulation.alphaTarget(0); d.fx=null; d.fy=null; }

window.addEventListener('DOMContentLoaded', ()=>{ 
  initGraph(); 
  loadAnalysis();
});
