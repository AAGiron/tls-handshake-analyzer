#adapted from https://github.com/plotly/dash-sample-apps/tree/main/apps/dash-clinical-analytics

import dash
from dash import dcc
from dash import html
from dash import dash_table
import plotly.graph_objs as go
import dash_uploader as du
from dash.dependencies import Input, Output, ClientsideFunction

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
				        ),
				        html.Br(),
				        html.H6("Performance Information:"),						
				        #Graphs
				        html.Div(id="size-graphs", className="row",				        
							children=[dcc.Graph(
						        id='size-per-artifact',
						        responsive=True, style={
	 								   #'display': 'block'
	 								   "width":400, "margin": 0,
	 								   'display': 'inline-block'
								},
						        figure=blank_figure()
						    ),
						    dcc.Graph(
						        id='size-per-app-data',
						        responsive=True, style={
						        		"width":400, "margin": 0,
	 								   'display': 'inline-block'
								},
						        figure=blank_figure()
						    )
						]),
					    dcc.Graph(
					        id='hs-timings',
					        responsive=True, style={
 								   'display': 'block'
							},
					        figure=blank_figure()
					    ),
					    html.Br(),
					    dash_table.DataTable(
				          id="summary_tls",
				          columns=[{'id': "hs_id", 'name': "Handshake (HS) Number"},
						          {'id': "total_hs", 'name': "Total HS Size"},
						          {'id': "hs_id", 'name': "HS Total Time (ms)"},
						          {'id': "hs_id", 'name': "HS Avg. Time (ms)"},
						          {'id': "hs_id", 'name': "HS Stdev. Time (ms)"}], 
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
				        html.Br(),
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
    app.run_server(debug=True)