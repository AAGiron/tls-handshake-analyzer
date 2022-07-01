#adapted from https://github.com/plotly/dash-sample-apps/tree/main/apps/dash-clinical-analytics
import time
import dash
import pandas as pd
from dash import dcc
from dash import html
from dash import dash_table
import plotly.graph_objs as go
import dash_uploader as du
from dash.dependencies import Input, Output, State

import pathlib

app = dash.Dash(
    __name__,
    prevent_initial_callbacks=True,
    meta_tags=[{"name": "viewport", "content": "width=device-width, initial-scale=1"}],
)
app.title = "TLS 1.3 Analyzer"


server = app.server
app.config.suppress_callback_exceptions = True

# Path
BASE_PATH = pathlib.Path(__file__).parent.resolve()
#DATA_PATH = BASE_PATH.joinpath("data").resolve()

UPLOAD_FOLDER = r"uploads"
du.configure_upload(app, UPLOAD_FOLDER)


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


def blank_figure():
    fig = go.Figure(go.Scatter(x=[], y = []))
    fig.update_layout(template = "plotly_dark")
#    fig.update_xaxes(showgrid = False, showticklabels = False, zeroline=False)
#    fig.update_yaxes(showgrid = False, showticklabels = False, zeroline=False)
    
    return fig


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
            ],
        ),
    ],
)



"""
	TLS Analyze (Start button)
	Tables are updated by dicts	
"""
@app.callback(
    Output('sec_info', 'data'),
    Output('insec_info', 'data'),
    Input('tlsanalyze-btn', 'n_clicks'),
    State('sec_info', 'data'),
    State('sec_info', 'columns'),
    State('insec_info', 'data'),
    State('insec_info', 'columns'),    
    )
def update_tables(n_clicks, secinfo_rows, secinfo_columns,
				insecinfo_rows, insecinfo_columns):
	secinfodict = {"ciphersuites": "",
			      "kexalgo": "",
			      "authalgo": "",
			      "hasech": ""
			    }
			    #

	if n_clicks > 0:
    	#sec_info table
		for c in secinfo_columns:
			secinfodict.update({c['id']: "red"})
    	
		secinfo_rows.append(secinfodict)

    	#insec information
		for c in insecinfo_columns:
			insecinfo_rows.append({c['id']:'Insecure Test'})

        
	return secinfo_rows, insecinfo_rows



@app.callback(
    Output('size-per-artifact', 'figure'),
    Output('size-per-app-data', 'figure'),
    Output('hs-timings', 'figure'),
    Input('tlsanalyze-btn', 'n_clicks'),       
    )
def update_all_figures(n_clicks):
	#fig1, fig2, fig3
	fig1 = blank_figure()
	fig2 = blank_figure()
	fig3 = blank_figure()
	if n_clicks > 0:
		fig1.update_layout(title="Size Per Artifacts")
		fig2.update_layout(title="Application data Payload")
		fig3.update_layout(title="Handshake Timings")

	return fig1, fig2, fig3




@app.callback(
    Output('summary_tls', 'data'),
    Input('tlsanalyze-btn', 'n_clicks'),    
    State('summary_tls', 'data'),
    State('summary_tls', 'columns'),    
    )
def update_summary_tables(n_clicks,summary_rows, summary_columns):
	summarydict = {"hs_id": "",
			      "total_hs_size": "",
			      "total_hs_time": "",
			      "avg_hs_time": "",
			      "stdev_hs_time": ""
			    }

	if n_clicks > 0:		
    	#summary_tls table
		for c in summary_columns:
			summarydict.update({c['id']: "test"})
    	
		summary_rows.append(summarydict)

        
	return summary_rows


# Run the server
if __name__ == "__main__":
    app.run_server(debug=True)