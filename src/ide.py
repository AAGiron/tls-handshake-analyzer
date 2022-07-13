# adapted from https://github.com/plotly/dash-sample-apps/tree/main/apps/dash-clinical-analytics
import time

import pandas as pd
import plotly.graph_objs as go
import dash_uploader as du

import dash
from dash import dcc
from dash import html
from dash import dash_table
from dash.dependencies import Input, Output, State

from callbacks import get_callbacks
from callbacks import blank_figure

app = dash.Dash(
    __name__,
    prevent_initial_callbacks=True,
    meta_tags=[{"name": "viewport",
                "content": "width=device-width, initial-scale=1"}],
)
app.title = "TLS 1.3 Handshake Analyzer"
app.config.suppress_callback_exceptions = True

# file upload configurations
UPLOAD_FOLDER = r"uploads"
du.configure_upload(app, UPLOAD_FOLDER, use_upload_id=False)

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
            #html.H3("TLS 1.3 Handshake Analyzer"),
            html.Img(src="assets/logo.png", className="responsiveimg"),
            # html.Div(
            #   id="intro",
            #children="Reads .pcap/.pcapng capture file and the corresponding TLS keylog file to show security information (such as ciphersuite usage) and performance (in terms of handshake time and size of cryptographic objects).",
            #children="Explore security information and performance from TLS captures.",
            # ),
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
                    # max_file_size=1800,  # 1800 Mb
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
                    # max_file_size=1800,  # 1800 Mb
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
                children=  [# html.Button(id="reset-btn", children="Reset", n_clicks=0),
                html.Button(id="tlsanalyze-btn", children="Start!", n_clicks=0),
                html.Button(id="reset-btn", children="Reset", n_clicks=0)
                ]
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
        # html.Div(
        #    id="banner",
        #    className="banner",
        # children=[html.Img(src=app.get_asset_url("plotly_logo.png"))],
        # ),
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
                        #html.H6("Security Information:"),
                        # Graphs
                        # html.Div(id="size-graphs", className="row",
                        # children=[
                        dcc.Graph(
                            id='size-per-artifact',
                            responsive=True, style={
                                # 'display': 'block'
                                # "width":400, "margin": 0,
                                # 'display': 'inline-block'
                                'display': 'block',
                                'height': '450px'
                            },
                            figure=blank_figure()
                        ),
                        # dcc.Graph(
                        #         id='size-per-app-data',
                        #         responsive=True, style={
                        #         		#"width":400, "margin": 0,
                        # 				   #'display': 'inline-block'
                        # 				   'display': 'block'
                        # 		},
                        #         figure=blank_figure()
                        # ),
                        # #]),
                        #    dcc.Graph(
                        #        id='hs-timings',
                        #        responsive=True, style={
                        # 			   'display': 'block'
                        # 	},
                        #        figure=blank_figure()
                        #    ),
                        html.Br(),
                        dash_table.DataTable(
                            id="sec_info",
                            style_as_list_view=True,
                            columns=[{'id': "ciphersuites", 'name': "Ciphersuites"},
                                     {'id': "kexalgo",
                                      'name': "KEX Algo."},
                                     {'id': "authalgo",
                                      'name': "Auth. Algo."},
                                     {'id': "hasech", 'name': "Supports ECH?"}],
                            data=[],
                            style_header={
                                'backgroundColor': '#222222',
                                'color': 'white',
                                'textAlign': 'left',
                                #'border': '0px'
                            },
                            style_data={
                                'backgroundColor':  '#222222',
                                                    'color': 'white',
                                'textAlign': 'left',
                                #'border': '0px'
                            },
                            style_data_conditional=[
                                {
                                    "if": {"state": "selected"},
                                    "backgroundColor": "inherit !important",
                                    "border": "inherit !important",
                                },
                                {
                                    'if': {
                                        'filter_query': '{kexalgo} contains "Not QS"',
                                        'column_id': 'kexalgo',
                                    },
                                    'color': 'tomato'
                                },
                                {
                                    'if': {
                                        'filter_query': '{kexalgo} contains "Is QS"',
                                        'column_id': 'kexalgo',
                                    },                                
                                    'color': '#3D9970'
                                },
                                {
                                    'if': {
                                        'filter_query': '{authalgo} contains "Not QS"',
                                        'column_id': 'authalgo',
                                    },
                                    'color': 'tomato'
                                },
                                {
                                    'if': {
                                        'filter_query': '{authalgo} contains "Is QS"',
                                        'column_id': 'authalgo',
                                    },
                                    'color': '#3D9970'
                                },

                            ],
                            tooltip_header={
                                'ciphersuites': 'Name of the TLS ciphersuite present in the handshake',
                                'kexalgo': 'Name of the Key Exchange algorithm used',
                                'authalgo': 'Name of the Authentication algorithm used to sign the handshake transcript',
                                'hasech': 'Checks if Encrypted Client Hello extension is provided',
                            },
                            css=[{
                                'selector': '.dash-table-tooltip',
                                'rule': 'background-color: grey; font-family: monospace; color: white'
                            }],
                            tooltip_duration=None,
                            tooltip_conditional=[
                            {
                                'if': {
                                    'filter_query': '{kexalgo} contains "Not QS"',                                    
                                    'column_id': 'kexalgo'
                                },
                                'value':'Not considered Quantum-safe. More info here: https://en.wikipedia.org/wiki/Post-quantum_cryptography',
                            },
                            {
                                'if': {
                                    'filter_query': '{authalgo} contains "Not QS"',
                                    'column_id': 'authalgo'
                                },
                                'value':'Not considered Quantum-safe. More info here:  https://en.wikipedia.org/wiki/Post-quantum_cryptography' 
                            },
                            {
                                'if': { 
                                    'filter_query': '{kexalgo} contains "Is QS"',                                    
                                    'column_id': 'kexalgo'
                                },
                                'value':'"Is QS" means that the algorithm is considered secure against the quantum computer. More info here: https://en.wikipedia.org/wiki/Post-quantum_cryptography',
                            },
                            {
                                'if': {
                                    'filter_query': '{authalgo} contains "Is QS"',
                                    'column_id': 'authalgo'
                                },
                                'value':'"Is QS" means that the algorithm is considered secure against the quantum computer. More info here: https://en.wikipedia.org/wiki/Post-quantum_cryptography',
                                'type': 'markdown',
                            }],
                        ),
                        html.Br(),
                        dash_table.DataTable(
                            id="insec_info",
                            columns=[
                                {'id': "insec_ciphersuites", 'name': "Insecure Ciphersuites Found:", 'type': 'text'}],
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
                            style_data_conditional=[
                                {
                                    'if': {
                                        'filter_query': '{insec_ciphersuites} contains "is considered insecure!"',
                                        'column_id': 'insec_ciphersuites',
                                    },
                                    'color': 'tomato'
                                },
                                {
                                    'if': {
                                        'filter_query': '{insec_ciphersuites} = "No insecure ciphersuite found"',
                                        'column_id': 'insec_ciphersuites',
                                    },
                                    'color': '#3D9970'
                                },
                                {
                                    'if': {
                                        'filter_query': '{insec_ciphersuites} contains "is considered weak!"',
                                        'column_id': 'insec_ciphersuites'
                                    },
                                    'backgroundColor': '#FFDC00',
                                    'color': 'white'
                                },
                                {
                                    "if": {"state": "selected"},
                                    "backgroundColor": "inherit !important",
                                    "border": "inherit !important",
                                }],
                            data=[],
                            tooltip_header={
                                'insec_ciphersuites': 'Name of the TLS ciphersuite present in the handshake that is considered insecure, based on https://ciphersuite.info  ',
                            },
                            css=[{
                                'selector': '.dash-table-tooltip',
                                'rule': 'background-color: grey; font-family: monospace; color: white'
                            }],
                            tooltip_duration=9000,
                        ),
                        html.Br(),
                        html.H6(
                            "Performance Information:"),
                        dash_table.DataTable(
                            id="summary_tls",
                            columns=[{'id': "hs_id", 'name': "Handshake (HS) Number"},
                                     {'id': "hs_size",
                                      'name': "HS Size (bytes)"},
                                     {'id': "hs_time",
                                      'name': "HS Time (ms)"},
                                     #{'id': "avg_hs_time", 'name': "HS Avg. Time (ms)"},
                                     #{'id': "stdev_hs_time", 'name': "HS Stdev. Time (ms)"}
                                     ],
                            data=[],
                            tooltip_header={
                                'hs_id': 'Sequential number of the Handshake',
                                'hs_size': 'Handshake size is computed by the sum of KEX and Authentication messages',
                                'hs_time': 'Handshake time is computed starting from the Client Hello message timestamp (provided by pcap file) until the client receives the Finished message from the Server. Note that this is the handshake time under the perspective of the client (the server also receives a finished message that ends the handshake).',
                            },
                            css=[{
                                'selector': '.dash-table-tooltip',
                                'rule': 'background-color: grey; font-family: monospace; color: white'
                            }],
                            tooltip_duration=9000,
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
                            style_data_conditional=[
                                {
                                    "if": {"state": "selected"},
                                    "backgroundColor": "inherit !important",
                                    "border": "inherit !important",
                                }
                            ]
                        ),
                    ],
                ),
                # html.Br(),
                # html.Div(id="summary",
                #	children=[

                # ]
                # ),
                html.Div(id='hidden-div-pcap', style={'display': 'none'}),
                html.Div(id='hidden-div-keylog', style={'display': 'none'}),
                html.Div(id='hidden-div-checklist', style={'display': 'none'}),
            ],
        ),
    ],
)
