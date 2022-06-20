#adapted from https://github.com/plotly/dash-sample-apps/tree/main/apps/dash-clinical-analytics

import dash
from dash import dcc
from dash import html
from dash.dependencies import Input, Output, ClientsideFunction

import numpy as np
import pandas as pd
import datetime
from datetime import datetime as dt
import pathlib

app = dash.Dash(
    __name__,
    meta_tags=[{"name": "viewport", "content": "width=device-width, initial-scale=1"}],
)
app.title = "TLS 1.3 Analyzer"


server = app.server
app.config.suppress_callback_exceptions = True

# Path
BASE_PATH = pathlib.Path(__file__).parent.resolve()
DATA_PATH = BASE_PATH.joinpath("data").resolve()

# Read data
#df = pd.read_csv(DATA_PATH.joinpath("clinical_analytics.csv.gz"))


def description_card():
    """
    :return: A Div containing dashboard title & descriptions.
    """
    return html.Div(
        id="description-card",
        children=[
            #html.H5("TLS 1.3 Analyzer"),
            html.H3("TLS 1.3 Analyzer"),
            html.Div(
                id="intro",
                #children="Reads .pcap/.pcapng capture file and the corresponding TLS keylog file to show security information (such as ciphersuite usage) and performance (in terms of handshake time and size of cryptographic objects).",
                children="Explore security information and performance from TLS captures.",
            ),
        ],
    )


def generate_control_card():
    """
    :return: A Div containing controls for graphs.
    """
    return html.Div(
        id="control-card",
        children=[
        	html.Br(),
            html.P("Select Capture file:"),
            dcc.Upload(
		        id='upload-data-pcap',
		        children=html.Div([
		            'Drag and Drop or ',
		            html.A('Select Files')
		        ]),
		        style={
		            'width': '100%',
		            'height': '60px',
		            'lineHeight': '60px',
		            'borderWidth': '1px',
		            'borderStyle': 'dashed',
		            'borderRadius': '5px',
		            'textAlign': 'center',
		            #'margin': '10px'
		        },
		        # Allow multiple files to be uploaded
		        multiple=False
    		),
            html.Br(),
            html.P("Select TLS keylog file:"),
            dcc.Upload(
		        id='upload-data-keylog',
		        children=html.Div([
		            'Drag and Drop or ',
		            html.A('Select Files')
		        ]),
		        style={
		            'width': '100%',
		            'height': '60px',
		            'lineHeight': '60px',
		            'borderWidth': '1px',
		            'borderStyle': 'dashed',
		            'borderRadius': '5px',
		            'textAlign': 'center',
		            #'margin': '10px'
		        },
		        # Allow multiple files to be uploaded
		        multiple=False
    		),        
            html.Br(),
            
            html.P("Options:"),
            dcc.Checklist(['Check Ciphersuite usage', 'Check Encrypted CH extensions'],
                      ['Check Ciphersuite usage', 'Check Encrypted CH extensions']
        	),
			html.Br(),		
            html.Div(
                id="reset-btn-outer",                
                children=#html.Button(id="reset-btn", children="Reset", n_clicks=0),
                html.Button(id="tlsanalyze-btn", children="Start!", n_clicks=0)
            ),
        ],
    )





app.layout = html.Div(
    id="app-container",
    children=[
        # Banner
        #html.Div(
        #    id="banner",
        #    className="banner",
            #children=[html.Img(src=app.get_asset_url("plotly_logo.png"))],
        #),
        # Left column
        html.Div(
            id="left-column",
            className="four columns",
            children=[description_card(), generate_control_card()]
            + [
                html.Div(
                    ["initial child"], id="output-clientside", style={"display": "none"}
                )
            ],
        ),
        # Right column
        html.Div(
            id="right-column",
            className="eight columns",
            children=[
                #Title
                html.Div(id="tls-title",
                	style={
			            'width': '100%',
			            'font-size': '12px',
		        	},
                	children=[
 	              		html.Pre("""
  ________   _____    __  __                __     __          __           ___                __                     
 /_  __/ /  / ___/   / / / /___ _____  ____/ /____/ /_  ____ _/ /_____     /   |  ____  ____ _/ /_  ______  ___  _____
  / / / /   \__ \   / /_/ / __ `/ __ \/ __  / ___/ __ \/ __ `/ //_/ _ \   / /| | / __ \/ __ `/ / / / /_  / / _ \/ ___/
 / / / /______/ /  / __  / /_/ / / / / /_/ (__  ) / / / /_/ / ,< /  __/  / ___ |/ / / / /_/ / / /_/ / / /_/  __/ /    
/_/ /_____/____/  /_/ /_/\__,_/_/ /_/\__,_/____/_/ /_/\__,_/_/|_|\___/  /_/  |_/_/ /_/\__,_/_/\__, / /___/\___/_/     
                                                                                             /____/                   
  """
            			)
                	],
                ),
                
                #html.Div(
                #    id="patient_volume_card",
                #    children=[
                #        html.B("Patient Volume"),
                #        html.Hr(),
                #        dcc.Graph(id="patient_volume_hm"),
                #    ],
                #),
                # Patient Wait time by Department
                #html.Div(
                #    id="wait_time_card",
                #    children=[
                #        html.B("Patient Wait Time and Satisfactory Scores"),
                #        html.Hr(),
                #        html.Div(id="wait_time_table", children=initialize_table()),
                #    ],
                #),
            ],
        ),
    ],
)


#@app.callback(
#    Output("patient_volume_hm", "figure"),
#    [
#        Input("date-picker-select", "start_date"),
#        Input("date-picker-select", "end_date"),
#        Input("clinic-select", "value"),
#        Input("patient_volume_hm", "clickData"),
##        Input("admit-select", "value"),
 #       Input("reset-btn", "n_clicks"),
 #   ],
#)

#app.clientside_callback(
#    ClientsideFunction(namespace="clientside", function_name="resize"),
#    Output("output-clientside", "children"),
#    [Input("wait_time_table", "children")] + wait_time_inputs + score_inputs,
#)


#@app.callback(
#    Output("wait_time_table", "children"),
#    [
#        Input("date-picker-select", "start_date"),
#        Input("date-picker-select", "end_date"),
#        Input("clinic-select", "value"),
#        Input("admit-select", "value"),
#        Input("patient_volume_hm", "clickData"),
#        Input("reset-btn", "n_clicks"),
#    ]
#    + wait_time_inputs
#    + score_inputs,
#)
#def update_table(start, end, clinic, admit_type, heatmap_click, reset_click, *args):
#    return table


# Run the server
if __name__ == "__main__":
    app.run_server(debug=False)