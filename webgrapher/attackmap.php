<!doctype html>
<meta charset="utf-8">
<html>
<head>
<title>MITRE ATT&CK Grapher</title>
<script src="d3.v5.min.js" charset="utf-8"></script>
<script src="dagre-d3.min.js"></script>
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
try {
  $json = file_get_contents($query);
  $obj = json_decode($json, true);
} catch (Exception $e) {
  die('Error.');
}
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
';

// Graph magic here

function emitDescription($parent, $key, $value, $show, $hide) {
  if ($key === "name") {
    if (is_array($value)) {
      $value = implode(', ', $value);
    }
    echo 'g.setNode("' . $value . '", { style: "fill: #aaffaa" }); ';
    echo "\n";
    if ($parent !== $value) {
      echo 'g.setEdge("' . $parent . '", "' . $value . '", { curve: d3.curveBasis });';
    }
  }
}
function emitGraph($parent, $key, $value, $show, $hide) {
  echo 'g.setNode("' . $key . '", { style: "fill: #aaffaa" });';
  echo "\n";
  echo 'g.setEdge("' . $parent . '", "' . $key . '", { curve: d3.curveBasis });';
  echo "\n";
  if (is_array($value)) {
    foreach ($value as $k => $v) {
      if (in_array($key, $show)) {
        emitGraph($key, $k, $v, $show, $hide);
      } else {
        emitDescription($key, $k, $v, $show, $hide);
      }
    }
  }
}
function emitTTPOverlap($parent, $key, $value) {
  $show = array('Actors', 'Malwares', 'Mitigations', 'Subtechniques', 'Tactics', 'Techniques', 'Tools');
  $hide = array('name', 'description', 'subtechnique_of', 'Matrices');
  if ($key === "name") {
    echo 'g.setNode("' . $value . '", { style: "fill: #aaffaa" });';
    echo "\n";
    echo 'g.setEdge("' . $parent . '", "' . $value . '", { curve: d3.curveBasis });';
    echo "\n";
  } else {
    echo 'g.setNode("' . $key . '", { style: "fill: #aaffaa" });';
    echo "\n";
    echo 'g.setEdge("' . $parent . '", "' . $key . '", { curve: d3.curveBasis });';
    echo "\n";
  }
  if (is_array($value)) {
    foreach ($value as $k => $v) {
      emitTTPOverlap($key, $k, $v);
    }
  }
}

function emitActorOverlap($parent, $key, $value, $show, $hide) {
  echo 'g.setNode("' . $key . '", { style: "fill: #aaffaa" });';
  echo "\n";
  echo 'g.setEdge("' . $parent . '", "' . $key . '", { curve: d3.curveBasis });';
  echo "\n";
  if (isset($value['name'])) {
    echo 'g.setNode("' . $value['name'] . '", { style: "fill: #aaffaa" });';
    echo "\n";
    echo 'g.setEdge("' . $key . '", "' . $value['name'] . '", { curve: d3.curveBasis });';
    echo "\n";
  }
}

// Main nodes
if ($q === "explore") {
  $show = array('Actors', 'Malwares', 'Mitigations', 'Subtechniques', 'Tactics', 'Techniques', 'Tools');
  $hide = array('name', 'description', 'subtechnique_of');
  $name = $obj['name'];
  if (is_array($name)) $name = implode(', ', $name);
  $description = $obj['description'];
  echo 'g.setNode("' . $name . '", { style: "fill: #aaffaa" }); ';
  echo "\n";
  foreach ($obj as $key => $value) {
    if (in_array($key, $show)) {
      emitGraph($name, $key, $value, $show, $hide);
    } else {
      emitDescription($name, $key, $value, $show, $hide);
    }
  }
}
if ($q === "ttpoverlap") {
  $show = array('Actors', 'Malwares', 'Mitigations', 'Subtechniques', 'Tactics', 'Techniques', 'Tools');
  $hide = array('name', 'description', 'subtechnique_of');
  foreach (array_keys($obj) as $matrix) {
    echo 'g.setNode("' . $matrix . '", { style: "fill: #aaffaa" }); ';
    echo "\n";
    foreach ($obj[$matrix] as $key => $value) {
      emitTTPOverlap($matrix, $key, $value);
    }
  }
}
if ($q === "actoroverlap") {
  $show = array('Actors', 'Malwares', 'Mitigations', 'Subtechniques', 'Tactics', 'Techniques', 'Tools');
  $hide = array('name', 'description', 'subtechnique_of');
  foreach ($obj as $type => $typearray) {
   if (in_array($type, $show)) {
      echo 'g.setNode("' . $type . '", { style: "fill: #aaffaa" }); ';
      echo "\n";
      foreach ($typearray as $key => $value) {
        emitActorOverlap($type, $key, $value, $show, $hide);
      }
    }
  }
  foreach ($obj['Actors'] as $actorname => $value) {
    echo 'g.setNode("' . $value['name'] . '", { style: "fill: #aaffaa" }); ';
    echo "\n";
    echo 'g.setEdge("' . $actorname . '", "' . $value['name'] . '", { curve: d3.curveBasis });';
    echo "\n";
    echo 'g.setNode("Matrices", { style: "fill: #aaffaa" }); ';
    echo "\n";
    echo 'g.setNode("' . $obj['Matrices']['name'] . '", { style: "fill: #aaffaa" }); ';
    echo "\n";
    echo 'g.setEdge("Matrices", "' . $obj['Matrices']['name'] . '", { curve: d3.curveBasis });';
    echo "\n";
    echo 'g.setEdge("' . $actorname . '", "Matrices", { curve: d3.curveBasis });';
    echo "\n";
    foreach ($obj as $type => $typearray) {
      if (in_array($type, $show)) {
        if ($type !== "Actors") {
          echo 'g.setEdge("' . $actorname . '", "' . $type . '", { curve: d3.curveBasis });';
          echo "\n";
        }
      }
    }
  }
}

echo '

// Create the renderer
var render = new dagreD3.render();

// Set up an SVG group so that we can translate the final graph.
var svg = d3.select("svg"), inner = svg.append("g");
// Run the renderer. This is what draws the final graph.
g.graph().rankDir = "LR";

render(inner, g);


// Center the graph
var xCenterOffset = (svg.attr("width") - g.graph().width) / 2;
inner.attr("transform", "translate(" + xCenterOffset + ", 20)");
svg.attr("height", g.graph().height + 40);
</script>
';
?>
</html>
