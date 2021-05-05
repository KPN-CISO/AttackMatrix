<!doctype html>
<meta charset="utf-8">
<html>
<head>
<title>MITRE ATT&CK Matrix Grapher</title>
<script src="https://d3js.org/d3.v5.min.js" charset="utf-8"></script>
<script src="dagre-d3.min.js"></script>
<script src="jquery-1.9.1.min.js"></script>
<script src="tipsy.js"></script>
<link rel="stylesheet" href="tipsy.css">
<style id="css">
text {
  font-weight: 300;
  font-family: "Helvetica Neue", Helvetica, Arial, sans-serf;
  font-size: 14px;
}

.node rect {
  stroke: #333;
  fill: #fff;
  stroke-width: 1.5px;
}

.edgePath path.path {
  stroke: #333;
  fill: none;
  stroke-width: 1.5px;
}

.arrowhead {
 stroke: blue;
 fill: blue;
 stroke-width: 1.5px;
}

.node text {
  pointer-events: none;
}

/* This styles the title of the tooltip */
.tipsy .name {
  font-size: 1.5em;
  font-weight: bold;
  color: #60b1fc;
  margin: 0;
}

/* This styles the body of the tooltip */
.tipsy .description {
  font-size: 1.2em;
}
</style>
<?php
if (isset($_GET['q'])) $q = strtolower($_GET['q']);
if (empty($q)) {
  die();
}
$api = 'http://149.210.137.179:8008/api';
if ($q === "explore") {
  if (isset($_GET['matrix'])) $matrix = $_GET['matrix'];
  if (isset($_GET['cat'])) $cat = $_GET['cat'];
  if (isset($_GET['id'])) $id = $_GET['id'];
  if (empty($matrix) or empty($cat) or empty($id)) {
    echo "<body>";
    echo "<b>Incorrect usage!</b>";
    echo "</body></html>";
    die();
  }
  $query = $api . '/explore/' . $matrix . '/' . $cat . '/' . $id;
}
if ($q === "ttpoverlap") {
  $ttp = $_GET['ttp'];
  $ttps = explode(',', $ttp);
  if (count($ttps) < 2) {
    echo "<body>";
    echo "<b>Incorrect usage! Choose at least two TTPs!<b/>";
    echo "</body></html>";
    die();
  } else {
    $query = $api . '/ttpoverlap/?ttp=' . implode('&ttp=', $ttps);
  }
}
if ($q === "actoroverlap") {
  $actor1 = $_GET['actor1'];
  $actor2 = $_GET['actor2'];
  if (empty($actor1) or empty($actor2)) {
    echo "<body>";
    echo "<b>Incorrect usage! Choose at least two actors!<b/>";
    echo "</body></html>";
    die();
  } else {
    $query = $api . '/actoroverlap/?actor1=' . $actor1 . '&actor2=' . $actor2;
  }
}
$json = file_get_contents($query);
$obj = json_decode($json, true);
if ($obj == "null") {
  echo "Empty result set: there is no <b>" . $id . "</b> in the <b>" . $cat . "</b> category in the <b>" . $matrix . "</b> matrix!";
  echo "<br />";
  print_r($json);
  echo "</body></html>";
  die();
}
?>
<svg id="svg" width=100% height=100%></svg>
<?php
echo '
<script>
var g = new dagreD3.graphlib.Graph().setGraph({});
var tooltips = {};

';

// Graph magic here
function emitGraph($parent=0, $key, $value) {
  $tooltips = array('name', 'description', 'subtechnique_of');
  if (!in_array($key, $tooltips)) {
    echo 'g.setNode("' . $key . '", { style: "fill: #aaffaa" });';
    echo "\n";
  }
  if (!in_array($key, $tooltips)) {
    if ($parent!==0) {
      echo 'g.setEdge("' . $parent . '", "' . $key . '", { curve: d3.curveBasis });';
      echo "\n";
    }
  }
  if ($key === 'description') {
    $description = json_encode($value);
    $short = str_replace("\n", "", (implode(' ', array_slice(explode(' ', $value), 0, 8)) . "..."));
    echo "tooltips[\"" . $short . "\"] = { description: " . $description . " };";
    echo "\n";
    echo 'g.setNode("' . $short . '", { style: "fill: #aaffaa" });';
    echo "\n";
    echo 'g.setEdge("' . $parent . '", "' . $short . '", { curve: d3.curveBasis });';
    echo "\n";
  }
  if (is_array($value)) {
    foreach ($value as $k => $v) {
        emitGraph($key, $k, $v);
    }
  }
}

// Explore
if ($q === "explore") {
  foreach ($obj as $key => $value) {
    emitGraph(0, $key, $value);
  }
}
// Actoroverlap
if ($q === "actoroverlap") {
  foreach ($obj as $key => $value) {
    emitGraph(0, $key, $value);
  }
}
if ($q === "ttpoverlap") {
  foreach ($obj as $key => $value) {
    emitGraph(0, $key, $value);
  }
}

echo '
Object.keys(tooltips).forEach(function(tooltip) {
  var value = tooltips[tooltip];
  value.label = tooltip;
  value.rx = value.ry = 5;
  g.setNode(tooltip, value);
});

// Create the renderer
var render = new dagreD3.render();

// Set up an SVG group so that we can translate the final graph.
var svg = d3.select("svg"),
  inner = svg.append("g");
// Run the renderer. This is what draws the final graph.
g.graph().rankDir = "LR";

var zoom = d3.zoom()
    .on("zoom", function() {
      inner.attr("transform", d3.event.transform);
    });
svg.call(zoom);

var styleTooltip = function(name, description) {
  return "<p class=\'name\'>" + name + "</p><p class=\'description\'>" + description + "</p>";
};

render(inner, g);

inner.selectAll("g.node")
  .attr("title", function(v) { return styleTooltip(v, g.node(v).description) })
  .each(function(v) { $(this).tipsy({ gravity: "w", opacity: 1, html: true }); });

// Center the graph
var xCenterOffset = (svg.attr("width") - g.graph().width) / 2;
inner.attr("transform", "translate(" + xCenterOffset + ", 20)");
svg.attr("height", g.graph().height + 40);
</script>
';
?>
</html>
