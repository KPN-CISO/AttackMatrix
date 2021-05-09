<!doctype html>
<meta charset="utf-8">
<html>
<head>
<title>MITRE ATT&CK Grapher</title>
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
  font-size: 1.5em;
}
</style>
<?php
if (isset($_GET['q'])) $q = strtolower($_GET['q']);
if (empty($q)) {
  echo "<body>";
  echo "<b>Incorrect usage! Specify an API method!<b/>";
  echo "</body></html>";
  die();
}
$api = 'http://localhost:8008/api';
if ($q === "explore") {
  $query = $api .= "/explore";
  if (isset($_GET['matrix'])) {
    $query .= '/' . $_GET['matrix'];
  }
  if (isset($_GET['cat'])) {
    $query .= '/' . $_GET['cat'];
  }
  if (isset($_GET['id'])) {
    $query .= '/' . $_GET['id'];
  }
}
if ($q === "ttpoverlap") {
  if (isset($_GET['ttp'])) {
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
  } else {
    echo "<body>";
    echo "<b>Incorrect usage! Choose at least two TTPs!<b/>";
    echo "</body></html>";
    die();
  }
}
if ($q === "actoroverlap") {
  if (isset($_GET['actor'])) {
    $actor = $_GET['actor'];
    $actors = explode(',', $actor);
    if (count($actors) < 2) {
      echo "<body>";
      echo "<b>Incorrect usage! Choose at least two Actors!<b/>";
      echo "</body></html>";
      die();
    } else {
      $query = $api . '/actoroverlap/?actor=' . implode('&actor=', $actors);
    }
  } else {
    echo "<body>";
    echo "<b>Incorrect usage! Choose at least two Actors!<b/>";
    echo "</body></html>";
    die();
  }
}
if ($q === "search") {
  if (isset($_GET['params'])) {
    $params = $_GET['params'];
    $query = $api . '/search/?params=' . urlencode($params);
  } else {
    echo "<body>";
    echo "<b>Incorrect usage! Specify a search paramater!<b/>";
    echo "</body></html>";
    die();
  }
}
try {
  $json = file_get_contents($query);
} catch (Exception $exception) {
  echo "Error communicating with the API!";
  echo "<br />";
  echo "</body></html>";
  die();
}
$obj = json_decode($json, true);
if (empty($obj)) {
  echo "Empty result set!";
  echo "<br />";
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
    $keysafe = json_encode($key);
    echo 'g.setNode(' . $keysafe . ', { style: "fill: #aaffaa" });';
    echo "\n";
  }
  if (!in_array($key, $tooltips)) {
    if ($parent!==0) {
      $parentsafe = json_encode($parent);
      $keysafe = json_encode($key);
      #echo 'g.setEdge(' . $parentsafe . ', ' . $keysafe . ', { curve: d3.curveBasis });';
      echo 'g.setEdge(' . $parentsafe . ', ' . $keysafe . ', {});';
      echo "\n";
    }
  }
  if ($key === 'description') {
    $description = json_encode($value);
    $short = str_replace("\n", "", (implode(' ', array_slice(explode(' ', $value), 0, 8)) . "..."));
    $shortsafe = json_encode($short);
    $parentsafe = json_encode($parent);
    echo 'tooltips[' . $shortsafe . '] = { description: ' . $description . ' };';
    echo "\n";
    echo 'g.setNode(' . $shortsafe . ', { style: "fill: #aaffaa" });';
    echo "\n";
    #echo 'g.setEdge(' . $parentsafe . ', ' . $shortsafe . ', { curve: d3.curveBasis });';
    echo 'g.setEdge(' . $parentsafe . ', ' . $shortsafe . ', {});';
    echo "\n";
  }
  if (is_array($value)) {
    foreach ($value as $k => $v) {
        emitGraph($key, $k, $v);
    }
  }
}

if (isset($q)) {
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
