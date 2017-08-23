# Game_of_thrones_wiki
A wiki page built from scratch for all GOT fans built using Jinja 2, bootstrap and google datastore and deployed on google app engine

## Accessing the demo<br /> 
https://gotwikidemo.appspot.com/


## Running a development version

### Requirements

- Google App Engine SDK for Python <a href="https://cloud.google.com/appengine/downloads#Google_App_Engine_SDK_for_Python">Download and install instructions</a>
- Clone this repository: ``` git clone https://github.com/as409/Game_of_thrones_wiki ```
 
 
 
### Run a development instance

- Run ```dev_appserver.py app.yaml``` . within the source directory
- Go to http://localhost:8080 in your browser
- Browse the application. Any edits to source files should reload the server automatically.

## Deploy to an App Engine instance

- Create a new project on cloud.google.com
- Run the command ``` gcloud init ``` and select the desired project
- Deploy with ``` gcloud app deploy app.yaml ``` (<a href="https://cloud.google.com/sdk/gcloud/reference/app/deploy">See the documentation)</a> in the source directory

![got](https://user-images.githubusercontent.com/17767383/29632899-038f3816-8862-11e7-9dbd-f80a4941260c.png)
