import streamlit as st
import pandas as pd
import plotly.express as px

df = pd.DataFrame({
    "IP": ["192.168.1.10"],
    "Count": [5]
})

st.write(df)

fig = px.bar(
    df,
    x="IP",
    y="Count",
    color="Count"
)

st.plotly_chart(fig)
