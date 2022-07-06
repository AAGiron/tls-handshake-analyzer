#adapted from https://github.com/plotly/dash-sample-apps/tree/main/apps/dash-clinical-analytics
import time
import dash
import pandas as pd
import plotly.graph_objs as go
import dash_uploader as du
import pathlib
from dash import dcc
from dash import html
from dash import dash_table
from dash.dependencies import Input, Output, State
from callbacks import get_callbacks
from callbacks import blank_figure

app = dash.Dash(
    __name__,
    prevent_initial_callbacks=True,
    meta_tags=[{"name": "viewport", "content": "width=device-width, initial-scale=1"}],
)
app.title = "TLS 1.3 Handshake Analyzer"

server = app.server
app.config.suppress_callback_exceptions = True

# Path
BASE_PATH = pathlib.Path(__file__).parent.resolve()

#file upload configurations
UPLOAD_FOLDER = r"uploads"
du.configure_upload(app, UPLOAD_FOLDER,use_upload_id=False)

# Get callbacks from callbacks.py
get_callbacks(app)

"""
Layout functions
"""
def description_card():
    """
    :return: A Div containing dashboard title & descriptions.
    """
    return html.Div(
        id="description-card",
        children=[
            #html.H5("TLS 1.3 Analyzer"),
            html.H3("TLS Handshake Analyzer"),
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
            html.Div(
            	id="cap-upload-area",
            	children=du.Upload(
            		id='pcap-uploader',
	                text='Drag and Drop files here',
	                text_completed='Completed: ',
	                pause_button=False,
	                cancel_button=True,
	                #max_file_size=1800,  # 1800 Mb
	                filetypes=['pcap', 'pcapng'],
	               	default_style=dict({'width': '100%',
	                					'minHeight': 1,
            							'lineHeight': 1}),
            	),
	        ),
            html.Br(),
            html.P("Select TLS keylog file:"),
            html.Div(
            	id="keylog-upload-area",
            	children=du.Upload(
            		id='keylog-uploader',
	                text='Drag and Drop files here',
	                text_completed='Completed: ',
	                pause_button=False,
	                cancel_button=True,
	                #max_file_size=1800,  # 1800 Mb
	                #filetypes=['pcap', 'pcapng'],
	                default_style=dict({'width': '100%',
	                					'minHeight': 1,
            							'lineHeight': 1}),
            	),
	        ),
            html.Br(),
            
            html.P("Options:"),
            dcc.Checklist(id="checklist", 
            			options={
				        	'cipher': 'Check Ciphersuite usage',
				        	'ech': 'Check ECH extension' 	
   						},
        	),
			html.Br(),		
            html.Div(
                id="reset-btn-outer",                
                children=#html.Button(id="reset-btn", children="Reset", n_clicks=0),
                html.Button(id="tlsanalyze-btn", children="Start!", n_clicks=0)
            ),
        ],
    )



"""
Main Layout
"""
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
            className="two columns",
            #style={'display': 'none'},
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
            className="nine columns",
            children=[
            	html.Br(),
                html.Div(
					id="security_information",
					children=[
						html.H6("Security Information:"),
						dash_table.DataTable(
				          id="sec_info",
				          style_as_list_view=True,
				          columns=[{'id': "ciphersuites", 'name': "Ciphersuites"}, 
				          {'id': "kexalgo", 'name': "KEX Algo."},
				          {'id': "authalgo", 'name': "Auth. Algo."},
				          {'id': "hasech", 'name': "Has ECH Support?"}],
				          data=[],
				          style_header={
						        'backgroundColor': '#222222',
						        'color': 'white',
						        'textAlign': 'left',
						        'border': '0px'
						  },
						  style_data={
						        'backgroundColor':  '#222222',
						        'color': 'white',
						        'textAlign': 'left',
						        'border': '0px'
						  },
				        ),  
				        html.Br(),
				        #we can use conditional formatting here: red for insecure, green for secure ciphers...
				        #https://dash.plotly.com/datatable/style
						dash_table.DataTable(
				          id="insec_info",
				          columns=[{'id': "insec_ciphersuites", 'name': "Insecure Ciphersuites Found:"}], 
				          style_as_list_view=True,
				          style_header={
						        'backgroundColor': '#222222',
						        'color': 'white',
						        'textAlign': 'left',
						        'border': '0px'
						  },
						  style_data={
						        'backgroundColor':  '#222222',
						        'color': 'white',
						        'textAlign': 'left',
								'border': '0px'
						  },
						  data=[],
				        ),
				        html.Br(),
				        html.H6("Performance Information:"),						
				        #Graphs
				        #html.Div(id="size-graphs", className="row",				        
							#children=[							
						dcc.Graph(
						        id='size-per-artifact',
						        responsive=True, style={
	 								   #'display': 'block'
	 								   #"width":400, "margin": 0,
	 								   #'display': 'inline-block'
	 								   'display': 'block'
								},
						        figure=blank_figure()
						),
						dcc.Graph(
						        id='size-per-app-data',
						        responsive=True, style={
						        		#"width":400, "margin": 0,
	 								   #'display': 'inline-block'
	 								   'display': 'block'
								},
						        figure=blank_figure()
						),
						#]),
					    dcc.Graph(
					        id='hs-timings',
					        responsive=True, style={
 								   'display': 'block'
							},
					        figure=blank_figure()
					    ),					    					    			      
					],
                ), 
                html.Br(),
                html.Div(id="summary",
					children=[
	                	dash_table.DataTable(
					          id="summary_tls",
					          columns=[{'id': "hs_id", 'name': "Handshake (HS) Number"},
							          {'id': "total_hs_size", 'name': "Total HS Size"},
							          {'id': "total_hs_time", 'name': "HS Total Time (ms)"},
							          {'id': "avg_hs_time", 'name': "HS Avg. Time (ms)"},
							          {'id': "stdev_hs_time", 'name': "HS Stdev. Time (ms)"}], 
					          data=[],
					          style_as_list_view=False,
					          style_header={
							        'backgroundColor': '#222222',
							        'color': 'white',
							        'textAlign': 'left',						        
							  },
							  style_data={
							        'backgroundColor':  '#222222',
							        'color': 'white',
							        'textAlign': 'left'
							  },
					    ),	
                	]
                ),               
                html.Div(id='hidden-div-pcap', style={'display':'none'}),
                html.Div(id='hidden-div-keylog', style={'display':'none'}),
                html.Div(id='hidden-div-checklist', style={'display':'none'}),
            ],
        ),
    ],
)


# Run the server
if __name__ == "__main__":
    app.run_server(debug=True)