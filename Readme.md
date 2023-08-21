<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MongoPass Repo</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .centered {
            display: flex;
            justify-content: center;
            align-items: center;
        }

        img {
            max-width: 100%;
            height: auto;
        }

        pre {
            background-color: #f6f6f6;
            padding: 15px;
            overflow-x: auto;
        }

        a {
            color: #337ab7;
            text-decoration: none;
        }

        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>

<div class="centered">
    <img src=".repoassets/BannerApp.png" alt="MongoPass Banner">
</div>

<h1>This is Mongo with Python app called MongoPass</h1>

<h2>The MongoPass CLI app</h2>
<img src=".repoassets/screenshot.png" alt="MongoPass Screenshot">

<h2>At Compass</h2>
<img src=".repoassets/screenshot_compass.png" alt="Compass Screenshot">

<h2>First step, the .env</h2>
<p>Please copy the <code>.env.example</code> file to <code>.env</code> and fill the variables with your own values.</p>

<pre>
cp .env.example .env
</pre>

<h2>To run the app</h2>
<pre>
python -m venv venv
source ./venv/Scripts/activate
pip install pymongo bcrypt python-decouple
python ./do.py
deactivate
</pre>

<div class="centered">
    <img src=".repoassets/IconApp.png" alt="Mongo Pass">
</div>

<h2>Pylar AI Creative ML Free License</h2>
<p>This project is licensed under the <a href="LICENSE.md">Pylar AI Creative ML Free License</a>. For further details about this license, please visit the <a href="https://huggingface.co/spaces/superdatas/free-license">official source HuggingFace/superdatas</a>.</p>

</body>
</html>
