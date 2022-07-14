import time
import dash
import pandas as pd
import plotly.graph_objs as go
import dash_uploader as du
import statistics
import wrapper
import requests
import json
from dash import dcc
from dash import html
from dash import dash_table
from dash.dependencies import Input, Output, State
from tlsobj.oid import nonQSKEX, nonQSAuth

pcap_latest_file = None
tlskeylog_latest_file = None


def get_callbacks(app):
    """
        Dash Callbacks
        First two are to set the file names (pcap and tls-keylog)
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


    """
        TLS Analyze (Start button)
    """
    @app.callback(
        Output('sec_info', 'data'),
        Output('insec_info', 'data'),
        Output('summary_tls', 'data'),
        Output('size-per-artifact', 'figure'),
        Output('reset-btn', 'n_clicks'),
        Input('tlsanalyze-btn', 'n_clicks'),
        Input('reset-btn', 'n_clicks'),
        Input("checklist", "value"),
        State('sec_info', 'data'),
        State('sec_info', 'columns'),
        State('insec_info', 'data'),
        State('insec_info', 'columns'),
        State('summary_tls', 'data'),        
        State('summary_tls', 'columns'),  
    )
    def update_tables_and_figure(n_clicks, reset_click, check_values, secinfo_rows, secinfo_columns,
                                 insecinfo_rows, insecinfo_columns,
                                 summary_rows, summary_columns):        

        i = 0
        fig1 = blank_figure()

        if 'cipher' in check_values:
            enable_ciphersuite_check = True
        else:
            enable_ciphersuite_check = False
        if 'ech' in check_values:
            enable_ech = True
        else:
            enable_ech = False

        #reset button
        if reset_click > 0 or pcap_latest_file is None:
            return [], [], [], fig1, 0

        figcolors = ['#0d0887', '#46039f', '#7201a8', '#9c179e', '#bd3786', '#d8576b', '#ed7953',
                     '#fb9f3a', '#fdca26', '#f0f921']  # ["darkslategrey","black", "gray","lightsteelblue"]
        hasInsecureCipher = False

        # parse:
        hslist = wrapper.startParsing(
            pcap_latest_file, tlskeylog_latest_file, enable_ech, enable_ciphersuite_check)

        # show results
        if n_clicks > 0:

            if isinstance(hslist, list):
                for hs in hslist:
                    i = i + 1
                    # sec_info table
                    if not enable_ech:
                        textech = "No"
                    else:
                        textech = "Yes"
                    
                    textKEX = hs.serverdata.getKEXNameFromGroup()
                    if textKEX in nonQSKEX:
                        textKEX = textKEX + " (Non-QS)"
                    else:
                        textKEX = textKEX + " (Is QS)"
                    textAuth = hs.certificateverify.signatureAlgo
                    if textAuth in nonQSAuth:
                        textAuth = textAuth + " (Non-QS)"
                    elif "N/A (No TLS log file)" not in textAuth:
                        textAuth = textAuth + " (Is QS)"
                    secinfo_rows.append({'ciphersuites': hs.ciphersuite.split(" ")[0],
                                         'kexalgo': textKEX,
                                         'authalgo': textAuth,
                                         'hasech': textech})

                    # insec information
                    if enable_ciphersuite_check:
                        resp, status = postCiphersuite(hs.ciphersuite)
                        if status == 200:
                            respjson = json.loads(resp.content)
                            securityInfo = respjson[hs.ciphersuite.split(" ")[
                                0]]['security']

                            if "insecure" in securityInfo:
                                insecinfo_rows.append({'insec_ciphersuites': hs.ciphersuite.split(" ")[
                                                      0] + " is considered insecure!"})
                                hasInsecureCipher = True
                            if "weak" in securityInfo:
                                insecinfo_rows.append(
                                    {'insec_ciphersuites': hs.ciphersuite.split(" ")[0] + " is considered weak!"})
                                hasInsecureCipher = True

                    # summary_tls table
                    hstimeprint = "{:.2f}".format(hs.hstime)
                    summary_rows.append(
                        {'hs_id': i, 'hs_size': hs.hssize, 'hs_time': hstimeprint})

                    # figure - size per message
                    x = ["CHello", "SHello", "Handshake Signature", "Certificates"]
                    y = [hs.chello.size, hs.serverdata.size,
                         hs.certificateverify.signatureLength,
                         hs.certificatedata.certsLength]
                    fig1.update_layout(title=dict(
                        text='<b>TLS Message Sizes</b>',
                        x=0.5,
                        y=0.95,
                        font=dict(
                            size=20,
                        )),
                        font=dict(
                        size=15,
                    ))

                    fig1.add_trace(go.Bar(
                        name='HS #'+str(i),
                        x=x, y=y,
                        marker_color=(figcolors[i % len(figcolors)]),
                        text=['%.0f' % elem for elem in y]
                    ))
                    # bargroupgap=0.15, bargap=0.3, width=900)
                    fig1.update_layout(barmode='group')
                    # , range=rangeG, type="log")
                    fig1.update_yaxes(title="Size (bytes)",
                                      showline=True, linewidth=1, linecolor='black')
                    fig1.update_xaxes(showline=True, linewidth=1,
                                      linecolor='black')

        if not hasInsecureCipher and enable_ciphersuite_check:
            insecinfo_rows.append(
                {'insec_ciphersuites': "No insecure ciphersuite found"})

        return secinfo_rows, insecinfo_rows, summary_rows, fig1,0


def blank_figure():
    fig = go.Figure(go.Scatter(x=[], y=[]))
    fig.update_layout(template="plotly_dark")
#    fig.update_xaxes(showgrid = False, showticklabels = False, zeroline=False)
#    fig.update_yaxes(showgrid = False, showticklabels = False, zeroline=False)

    return fig


def postCiphersuite(ciphersuite):

    inputURL = "https://ciphersuite.info/api/cs/"+ciphersuite.split(" ")[0]
    resp = requests.post(inputURL)
    return resp, resp.status_code
