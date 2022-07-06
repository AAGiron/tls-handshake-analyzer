import time
import dash
import pandas as pd
import plotly.graph_objs as go
import dash_uploader as du
import statistics
import wrapper
from dash import dcc
from dash import html
from dash import dash_table
from dash.dependencies import Input, Output, State

pcap_latest_file = ""
tlskeylog_latest_file = ""

#user options configurations
enable_ech = False
enable_ciphersuite_check = False

def get_callbacks(app):
    """
        Dash Callbacks
    """
    @du.callback(
        output=Output("hidden-div-pcap", "children"),
        id="pcap-uploader",
    )
    def callback_setpcapfile(filenames):    
        global pcap_latest_file
        pcap_latest_file = filenames[0]
        return None

    @du.callback(
        output=Output("hidden-div-keylog", "children"),
        id="keylog-uploader",
    )
    def callback_setkeylogfile(filenames):
        global tlskeylog_latest_file 
        tlskeylog_latest_file = filenames[0]
        return None


    @app.callback(
        Output("hidden-div-checklist", "children"),
        Input("checklist", "value"),    
        )
    def update_checklist_selection(check_values):
        if 'cipher' in check_values:
            enable_ciphersuite_check = True
        if 'ech' in check_values:
            enable_ech = True 


    """
        TLS Analyze (Start button)
        Tables are updated by dicts 
    """
    @app.callback(
        Output('sec_info', 'data'),
        Output('insec_info', 'data'),
        Output('summary_tls', 'data'),
        Input('tlsanalyze-btn', 'n_clicks'),     
        State('sec_info', 'data'),
        State('sec_info', 'columns'),
        State('insec_info', 'data'),
        State('insec_info', 'columns'),     
        State('summary_tls', 'data'),
        State('summary_tls', 'columns'),     
        )
    def update_tables(n_clicks, secinfo_rows, secinfo_columns,
                      insecinfo_rows, insecinfo_columns,
                      summary_rows, summary_columns):
        secinfodict = {"ciphersuites": "",
                      "kexalgo": "",
                      "authalgo": "",
                      "hasech": ""
                    }                    
        i = 0

        #parse:        
        hslist = wrapper.startParsing(pcap_latest_file,tlskeylog_latest_file,enable_ech,enable_ciphersuite_check)

        #show results
        if n_clicks > 0:
            
            for hs in hslist:
                i = i + 1
                #sec_info table                                        
                secinfo_rows.append({'ciphersuites': hs.ciphersuite,
                    'kexalgo': hs.serverdata.getKEXNameFromGroup(),
                    'authalgo': hs.certificateverify.signatureAlgo,
                    'hasech': "Not implemented yet"})

                #insec information
                for c in insecinfo_columns:
                    insecinfo_rows.append({c['id']:'Not implemented yet'})

                #summary_tls table
                hstimeprint = "{:.2f}".format(hs.hstime)            
                summary_rows.append({'hs_id': i, 'hs_size': hs.hssize, 'hs_time': hstimeprint})
            
        return secinfo_rows, insecinfo_rows, summary_rows



    # @app.callback(
    #     Output('size-per-artifact', 'figure'),
    #     Output('size-per-app-data', 'figure'),
    #     Output('hs-timings', 'figure'),
    #     Input('tlsanalyze-btn', 'n_clicks'),       
    #     )
    # def update_all_figures(n_clicks):
    #     #fig1, fig2, fig3
    #     fig1 = blank_figure()
    #     fig2 = blank_figure()
    #     fig3 = blank_figure()
    #     if n_clicks > 0:
    #         fig1.update_layout(title="Size Per Artifacts")
    #         fig2.update_layout(title="Application data Payload")
    #         fig3.update_layout(title="Handshake Timings")

    #     return fig1, fig2, fig3




def blank_figure():
    fig = go.Figure(go.Scatter(x=[], y = []))
    fig.update_layout(template = "plotly_dark")
#    fig.update_xaxes(showgrid = False, showticklabels = False, zeroline=False)
#    fig.update_yaxes(showgrid = False, showticklabels = False, zeroline=False)
    
    return fig


