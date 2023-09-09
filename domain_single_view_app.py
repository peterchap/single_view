import streamlit as st
import pandas as pd
import aiohttp
import asyncio
import asyncwhois
import certifi
import io
import socket
import ssl
import sys
import time
from bs4 import BeautifulSoup
from datetime import datetime
from googletrans import Translator
from PIL import Image
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager


headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
}


@st.cache_resource
def get_driver():
    return webdriver.Chrome


async def get_any(session, domain):
    url = f"https://dns.google.com/resolve?name={domain}&type=ANY"
    async with session.get(url) as resp:
        response = await resp.json(encoding="latin-1")

        if "Answer" in response:
            df = pd.DataFrame.from_dict(response["Answer"]).replace(",", "", regex=True)
            df = df[~df["data"].str.contains("invalid")]
            if 13 in df["type"].values:
                y = await get_domain_type13(session, domain)
            else:
                try:
                    df = df.loc[df["type"].isin([1, 2, 5, 15, 16])]
                    try:
                        a = df["data"].loc[df["type"] == 1].values[0]
                    except:
                        a = "No A"
                    try:
                        ns = (
                            df["data"]
                            .loc[df["type"] == 2]
                            .values[0]
                            .rstrip(".")
                            .lower()
                        )
                    except:
                        ns = "No NS"
                    try:
                        cname = (
                            df["data"]
                            .loc[df["type"] == 5]
                            .values[0]
                            .rstrip(".")
                            .lower()
                        )
                    except:
                        cname = "No CNAME"
                    try:
                        mx = (
                            df["data"]
                            .loc[df["type"] == 15]
                            .values[0]
                            .rstrip(".")
                            .lower()
                        )
                        mx = mx.split(" ")[1]
                    except:
                        mx = "No MX"
                    try:
                        spf = (
                            df["data"]
                            .loc[
                                (df["type"] == 16)
                                & df["data"].str.contains("spf", regex=False)
                            ]
                            .values[0]
                        )
                        if len(spf) > 100:
                            spf = spf[0:99]
                    except:
                        spf = "No SPF"
                    try:
                        www, ptr = await get_www(session, domain)
                    except:
                        www = "No WWW"
                        ptr = "No PTR"
                    try:
                        mail = await get_mail(session, domain)
                    except:
                        mail = "No Mail"
                    y = f"{domain},{'Response OK'},{a},{ns},{cname},{mx},{spf},{www},{ptr},{mail}"
                except:
                    a = "No A"
                    ns = "No NS"
                    cname = "No CNAME"
                    mx = "No MX"
                    spf = "No SPF"
                    www = "No WWW"
                    ptr = "No PTR"
                    mail = "No Mail"
                    y = f"{domain},{'No DNS Records'},{a},{ns}{cname},{mx},{spf},{www},{ptr},{mail}\n"
        else:
            y = f"{domain},{'No DNS Records'},{'no a'},{'no ns'},{'no cname'},{'no mx'},{'no spf'},{'No www'},{'No ptr'},{'No mail'}\n"
        # print(y)
        # z = re.sub('[^a-zA-Z0-9.,=:~ \n]+', '', y)
        # print(z)
        return y


async def get_domain_type13(session, domain):
    ns = await get_ns(session, domain)
    a = await get_A(session, domain)
    cname = await get_cname(session, domain)
    mx = await get_mx(session, domain)
    spf = await get_spf(session, domain)
    www, ptr = await get_www(session, domain)
    mail = await get_mail(session, domain)
    return f"{domain},{'Resolved 13'},{a},{ns},{cname},{mx},{spf},{www},{ptr},{mail}"


async def get_ns(session, domain):
    url = f"https://dns.google.com/resolve?name={domain}&type=NS"
    async with session.get(url) as resp:
        response = await resp.json(encoding="latin-1")
        if "Answer" in response:
            df = pd.DataFrame.from_dict(response["Answer"])
            try:
                ns = df["data"].loc[df["type"] == 2].values[0].rstrip(".").lower()
            except:
                ns = "No NS"
        else:
            ns = "No NS"
    return ns


async def get_cname(session, domain):
    url = f"https://dns.google.com/resolve?name={domain}&type=CNAME"
    async with session.get(url) as resp:
        response = await resp.json(encoding="latin-1")
        if "Answer" in response:
            df = pd.DataFrame.from_dict(response["Answer"])
            try:
                cname = df["data"].loc[df["type"] == 2].values[0].rstrip(".").lower()
            except:
                cname = "No CNAME"
        else:
            cname = "No CNAME"
    return cname


async def get_A(session, domain):
    url = f"https://dns.google.com/resolve?name={domain}&type=A"
    async with session.get(url) as resp:
        response = await resp.json(encoding="latin-1")
        if "Answer" in response:
            df = pd.DataFrame.from_dict(response["Answer"])
            try:
                a = df["data"].loc[df["type"] == 1].values[0]
            except:
                a = "No A"
        else:
            a = "No A"
    return a


async def get_mx(session, domain):
    url = f"https://dns.google.com/resolve?name={domain}&type=MX"
    async with session.get(url) as resp:
        response = await resp.json(encoding="latin-1")
        if "Answer" in response:
            df = pd.DataFrame.from_dict(response["Answer"])
            try:
                mx = df["data"].loc[df["type"] == 15].values[0].rstrip(".").lower()
                mx = mx.split(" ")[1]
            except:
                mx = "No MX"
        else:
            mx = "No MX"
    return mx


async def get_spf(session, domain):
    url = f"https://dns.google.com/resolve?name={domain}&type=TXT"
    async with session.get(url) as resp:
        response = await resp.json(encoding="latin-1")
        if "Answer" in response:
            df = pd.DataFrame.from_dict(response["Answer"])
            try:
                spf = (
                    df["data"]
                    .loc[
                        (df["type"] == 16)
                        & (df["data"].str.contains("spf", regex=False))
                    ]
                    .values[0]
                )
            except:
                spf = "No SPF"
        else:
            spf = "No SPF"
    return spf


async def get_www(session, domain):
    url = f"https://dns.google.com/resolve?name=www.{domain}&type=A"
    async with session.get(url) as resp:
        response = await resp.json(encoding="latin-1")
        if "Answer" in response:
            df = pd.DataFrame.from_dict(response["Answer"])
            try:
                www = df["data"].loc[df["type"] == 1].values[0]
                ptr = ptr_lookup(www)
            except:
                www = "No A"
                ptr = "No PTR"
        else:
            www = "No A"
            ptr = "No PTR"
    return www, ptr


async def get_mail(session, domain):
    url = f"https://dns.google.com/resolve?name=mail.{domain}&type=A"
    async with session.get(url) as resp:
        response = await resp.json(encoding="latin-1")
        if "Answer" in response:
            df = pd.DataFrame.from_dict(response["Answer"])
            try:
                mail = df["data"].loc[df["type"] == 1].values[0]
            except:
                mail = "No Mail"
        else:
            mail = "No Mail"
    return mail


def ptr_lookup(ip):
    try:
        ptr = socket.gethostbyaddr(ip)[0]
    except:
        ptr = "No PTR"
    return ptr


async def get_create_date(domain):
    try:
        result = asyncwhois.whois_domain(domain)
        result1 = result.parser_output

        if isinstance(result1["created"], str):
            date = result1["created"]
        elif isinstance(result1["created"], datetime):
            date = result1["created"].strftime("%d/%m/%Y")
        elif result1["created"] is None:
            date = "No Date"
        else:
            date = result1["created"].strftime("%d/%m/%Y")
    except:
        date = "No Whois"
    return date


async def parse(session, domain):
    url = "https://" + domain

    try:
        r = await session.get(url, allow_redirects=True)
    except:
        r = None
        print("%s has error '%s'" % (domain, sys.exc_info()[0]))

    if r is None:
        return (
            domain,
            "Connect Error",
            "No Title",
            "No Description",
            "No classification",
            "No langauge",
            "No translation",
        )
    else:
        async with session.get(url, allow_redirects=True) as resp:
            if resp.status != 200:
                pass
            html = await resp.text()

            soup = BeautifulSoup(html, "html.parser")

            if soup.title is not None:
                title = soup.title.text
            elif ((soup.find("meta", attrs={"property": "og:title"}))) is not None:
                title = soup.find("meta", attrs={"property": "og:title"}).get("content")
            else:
                title = "No Title"

            if ((soup.find("meta", attrs={"property": "og:description"}))) is not None:
                desc = soup.find("meta", attrs={"property": "og:description"}).get(
                    "content"
                )

            elif (soup.find("meta", attrs={"name": "description"})) is not None:
                desc = soup.find("meta", attrs={"name": "description"}).get("content")
            else:
                desc = "No Description"

            text = str(title).lower() + " " + str(desc).lower()

            language = await language_check(text)

            park = park_check(soup, domain)

            return park[1], title, desc, language[0], language[1], language[2]


def park_check(soup, domain):
    soup1 = str(soup)
    if f"The domain name {domain} is for sale" in soup1:
        park = "Parked1"
    elif "window.park" in soup1:
        park = "Parked2"
    elif f"{domain} domain name is for sale. Inquire now." in soup1:
        park = "Parked3"
    elif "This domain {domain} may be for sale!" in soup1:
        park = "Parked4"
    else:
        park = "Not Parked"
    return domain, park


async def language_check(text):
    translator = Translator()
    language = translator.detect(text).lang
    if language != "en":
        translated = translator.translate(text).text.lower()
    else:
        translated = text

    if "host" in (translated):
        category = "Hosting"
    elif "cloud" in str(translated):
        category = "Hosting"
    elif "server" in str(translated):
        category = "Hosting"
    elif "telephony" in str(translated):
        category = "Hosting"
    elif "internet" in str(translated):
        category = "Telecoms"
    elif "isp" in str(translated):
        category = "Hosting"
    elif "tele" in str(translated):
        category = "Telecoms"
    elif "it service" in str(translated):
        category = "IT Services"
    elif "it Support" in str(translated):
        category = "IT Services"
    elif "it consult" in str(translated):
        category = "IT Services"
    elif "it solution" in str(translated):
        category = "IT Services"
    elif "digital solution" in str(translated):
        category = "IT Services"
    elif "outsource" in str(translated):
        category = "IT Services"
    elif "domain" in str(translated):
        category = "Domain Mgmt"
    elif "mail" in str(translated):
        category = "Email Services"

    elif "marketing" in str(translated):
        category = "Marketing"
    elif "ecommerce" in str(translated):
        category = "Ecommerce"
    elif "e-commerce" in str(translated):
        category = "Ecommerce"
    elif "website" in str(translated):
        category = "Web Agency"
    elif "web design" in str(translated):
        category = "Web Agency"
    elif "graphic design" in str(translated):
        category = "Web Agency"
    elif "agency" in str(translated):
        category = "Agency"
    elif "security" in str(translated):
        category = "Email Security"
    elif "anti-spam" in str(translated):
        category = "Email Security"
    elif "education" in str(translated):
        category = "Education"
    elif "university" in str(translated):
        category = "Education"
    elif "no title no description" in str(translated):
        category = "Check"
    else:
        category = "Other"
    return category, language, translated


options = Options()
options.add_argument("--disable-gpu")
options.add_argument("--headless")


def capture_screenshot(url, thumbnail_size=(300, 200)):
    """# Set up the driver and open the URL
    options = webdriver.ChromeOptions()
    options.headless = True
    driver = webdriver.Chrome(options=options)
    """
    driver = get_driver()
    driver.get(url)

    # Take a screenshot
    screenshot = driver.get_screenshot_as_png()
    driver.quit()

    # Convert to PIL Image and create thumbnail
    image = Image.open(io.BytesIO(screenshot))
    image.thumbnail(thumbnail_size)
    # image.save("thumbnail.png")
    return image


async def main(domain):
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    conn = aiohttp.TCPConnector(ssl=ssl_context)

    async with aiohttp.ClientSession(connector=conn, headers=headers) as session:
        try:
            r = await session.get(f"https://dns.google/resolve?name={domain}&type=ANY")
        except:
            r = None
            print("%s has error '%s'" % (domain, sys.exc_info()[0]))
        if r is None:
            print(domain, "does not exist")

        else:
            dns = (await get_any(session, domain)).split(",")
            dnskeys = [
                "Domain",
                "Response",
                "A",
                "NS",
                "CNAME",
                "MX",
                "SPF",
                "WWW",
                "PTR",
                "Mail",
            ]
            result = dict(zip(dnskeys, dns))
            date = await get_create_date(domain)
            datedict = {"Create Date": date}
            result.update(datedict)
            # print(result)
            site = await parse(session, domain)
            sitedict = dict(
                zip(
                    [
                        "Parked",
                        "Title",
                        "Description",
                        "Category",
                        "Language",
                        "Translation",
                    ],
                    site,
                )
            )
            result.update(sitedict)
            return result


@st.cache_data()
def load_data(input):
    data = asyncio.run(main(input))
    return data


@st.cache_data()
def www_image(url):
    image = capture_screenshot(url)
    return image


# Replace with your target URL
with open("style.css") as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

st.title("Domain Single View")
input = st.text_input("Enter Domain", "esbconnect.com")
url = "https://www." + input + "/"
st.write("Fetching Data for: ", url)
with st.spinner("Wait for it..."):
    time.sleep(5)
st.success("Done!")
data = load_data(input)
df = pd.DataFrame.from_dict(data, orient="index")
df_domain = df[df.index.isin(["Domain", "Create Date", "NS", "A", "CNAME"])]

df_domain_style = df_domain.style.hide(axis="columns").set_properties(
    **{"text-align": "left"}
)
image = www_image(url)
col1, col2 = st.columns(2)
with col1:
    st.subheader("Domain Info")
    st.write(df_domain_style.to_html(), unsafe_allow_html=True)
with col2:
    st.subheader("Email Info")
    st.write("MX: ", data["MX"])
    st.write("SPF: ", data["SPF"])
    st.write("Mail: ", data["Mail"])
with st.container():
    st.subheader("Website Info")
    (
        col1,
        col2,
    ) = st.columns(2)
    with col1:
        st.write("WWW: ", data["WWW"])
        st.write("PTR: ", data["PTR"])
        st.write("Parked: ", data["Parked"])
    with col2:
        st.image(image, caption="Website Screenshot")
        st.markdown(f'<a href="{url}">Website Link</a>', unsafe_allow_html=True)
    st.write("Title: ", data["Title"])
    st.write("Description: ", data["Description"])
    st.write("Category: ", data["Category"])
    st.write("Language: ", data["Language"])
    st.write("Translation: ", data["Translation"])
