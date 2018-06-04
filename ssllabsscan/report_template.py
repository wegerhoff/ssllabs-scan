REPORT_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{{VAR_TITLE}}</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
<h1>{{VAR_TITLE}}</h1>
<table class="tftable" border="1">
{{VAR_DATA}}
</table>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.9.1/jquery.min.js"></script>
<script src="./stickytableheader.js"></script>
<script>
	$("table").stickyTableHeaders();
</script>
</body>
</html>
"""
