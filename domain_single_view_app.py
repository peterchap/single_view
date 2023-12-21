import streamlit as st
import pandas as pd
import aiohttp
import asyncio
import dns.asyncresolver
import asyncwhois
import certifi
import io
import re
import socket
import ssl
import sys
import time
import tldextract
import urllib.robotparser
import datetime
from bs4 import BeautifulSoup
from datetime import datetime, date
from googletrans import Translator
from PIL import Image
from selenium import webdriver
from selenium.webdriver.common.by import By

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
}

resolver = dns.asyncresolver.Resolver()
resolver.lifetime = 2.0
resolver.timeout = 2.0

extract = tldextract.TLDExtract(include_psl_private_domains=True)

st.set_page_config(layout="wide")


@st.cache_resource
def get_driver():
    return webdriver.Chrome()


def mxToString(list):
    join = ", "
    str1 = ""
    for ele in list:
        ele1 = ele.replace(",", ":").rstrip(".")
        str1 += ele1 + join
    return str1


def listToString(list):
    join = ", "
    str1 = ""
    for ele in list:
        str1 += ele + join
    str1 = str1.rstrip(", ")
    return str1


def extract_registered_domain(mx_record):
    reg = extract(mx_record).registered_domain
    suffix = extract(mx_record).suffix
    return reg, suffix


def extract_suffix(domain):
    result = extract(domain).suffix
    return result

    def check_robots_txt(domain: str):
        """
        Check if the site's robots.txt allows collecting the home page HTML.
        :param str domain: Domain of the site.
        :return: True if allowed, False otherwise.
        """
        rp = urllib.robotparser.RobotFileParser()
        rp.set_url(f"https://{domain}/robots.txt")
        rp.read()
        return rp.can_fetch("*", f"https://{domain}/")


async def fetch_url(domain: str):
    """
    Fetch raw HTML from a URL prior to parsing.
    :param ClientSession session: Async HTTP requests session.
    :param str url: Target URL to be fetched.
    :param AsyncIOFile outfile: Path of local file to write to.
    :param int total_count: Total number of URLs to be fetched.
    :param int i: Current iteration of URL out of total URLs.
    """
    extract = tldextract.TLDExtract(include_psl_private_domains=True)
    extract.update()
    valid_pattern = re.compile(r"[^a-zA-Z0-9.-]")
    domain = valid_pattern.sub("", domain)
    suffix = extract_suffix(domain)
    a = await get_A(domain)
    ns = await get_ns(domain)
    cname = await get_cname(domain)
    mx, mx_domain, mx_suffix = await get_mx(domain)
    spf = await get_spf(domain)
    dmarc = await get_dmarc(domain)
    www, www_ptr, www_cname = await get_www(domain)
    (
        mail_a,
        mail_mx,
        mail_mx_domain,
        mail_suffix,
        mail_spf,
        mail_dmarc,
        mail_ptr,
    ) = await get_mail(domain)
    create_date = await get_create_date(domain)
    refresh_date = date.today()

    # LOGGER.info(f"Processed {batch +i+1} of {total_count} URLs.")

    return [
        domain,
        suffix,
        a,
        cname,
        ns,
        mx,
        mx_domain,
        mx_suffix,
        spf,
        dmarc,
        www,
        www_ptr,
        www_cname,
        mail_a,
        mail_mx,
        mail_mx_domain,
        mail_suffix,
        mail_spf,
        mail_dmarc,
        mail_ptr,
        create_date,
        refresh_date,
    ]


async def get_A(domain):
    try:
        result = await resolver.resolve(domain, "A")
        a = []
        for rr in result:
            a.append(rr.to_text())
        a = listToString(a).rstrip(",")
    except Exception as e:
        a = "None"
    return a


async def get_ns(domain):
    try:
        result = await resolver.resolve(domain, "NS")
        ns = []
        for rr in result:
            ns.append(rr.to_text().rstrip("."))
        ns = listToString(ns).rstrip(",")
    except Exception as e:
        ns = e
    return ns


async def get_cname(domain):
    try:
        answers = await resolver.resolve(domain, "CNAME")
        cname = []
        for cn in answers:
            cname.append(cn.to_text().rstrip("."))
        cname = listToString(cname).rstrip(",")
    except dns.resolver.NoAnswer as e:
        cname = "None"
    except Exception as e:
        cname = "None"
    return cname


async def get_mx(domain):
    try:
        result = await resolver.resolve(domain, "MX")
        mx = []
        for rr in result:
            mx.append(f"{rr.preference}, {rr.exchange}")
        mx = mxToString(mx).rstrip(", ")
        split = mx.split(":")[1].strip().split(",")[0]
        mx_domain, suffix = extract_registered_domain(split)
    except Exception as e:
        mx = "None"
        mx_domain = None
        suffix = None
    return mx, mx_domain, suffix


async def get_ptr(ip):
    try:
        ptr = socket.getfqdn(ip)
        if ptr == ip:
            ptr = "None"
    except Exception as e:
        ptr = e
    return ptr


async def get_www(domain):
    www = await get_A("www." + domain)
    if www == "No A":
        www_ptr = "None"
    else:
        www_ptr = await get_ptr(www.split(", ")[0])
    www_cname = await get_cname("www." + domain)

    return www, www_ptr, www_cname


async def get_mail(domain):
    mail_a = await get_A("mail." + domain)
    mail_mx, mail_mx_domain, mail_suffix = await get_mx("mail." + domain)
    if mail_a != "No A":
        mail_ptr = await get_ptr(mail_a.split(", ")[0])
    else:
        mail_ptr = "None"

    mail_spf = await get_spf("mail." + domain)
    mail_dmarc = await get_dmarc("mail." + domain)

    return mail_a, mail_mx, mail_mx_domain, mail_suffix, mail_spf, mail_dmarc, mail_ptr


async def get_spf(domain):
    try:
        result = await resolver.resolve(domain, "TXT")
        spf = None
        for rr in result:
            if "spf" in rr.to_text().lower():
                spf = rr.to_text().strip('"')
        if spf is None:
            spf = "None"
    except Exception as e:
        spf = "None"
    return spf


async def get_dmarc(domain):
    try:
        result = await resolver.resolve("_dmarc." + domain, "TXT")
        dmarc = None
        for rr in result:
            if "dmarc" in rr.to_text().lower():
                dmarc = rr.to_text().strip('"')
        if dmarc is None:
            dmarc = "None"
    except Exception as e:
        dmarc = "None"
    return dmarc


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
    except Exception as e:
        date = e
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
    trans = Translator()
    language = trans.detect(text).lang
    if language != "en":
        translated = trans.translate(text).text.lower()
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


# options = Options()
# options.add_argument("--disable-gpu")
#


def capture_screenshot(domain, thumbnail_size=(300, 200)):
    driver = webdriver.Chrome()

    try:
        driver.get(f"https://www.{domain}/")
        try:
            elem = driver.find_element(By.XPATH, "//meta[@name='description']")
        except:
            elem = "No description found"
        try:
            screenshot = driver.get_screenshot_as_png()
            image = Image.open(io.BytesIO(screenshot))
        except:
            image = Image.open("E:/rapid7/no-website.png")

    except:
        image = Image.open("E:/rapid7/no-website.png")

    # Set up the driver and open the URL

    return image


async def main(domain):
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    conn = aiohttp.TCPConnector(ssl=ssl_context)
    async with aiohttp.ClientSession(connector=conn, headers=headers) as session:
        try:
            r = get_ns(domain)
        except:
            r = None
            print("%s has error '%s'" % (domain, sys.exc_info()[0]))
        if r is None:
            print(domain, "does not exist")
        else:
            dns = await fetch_url(domain)
            dnskeys = [
                "Domain",
                "Suffix",
                "A",
                "CNAME",
                "NS",
                "MX",
                "MX_Domain",
                "MX_Suffix",
                "SPF",
                "DMARC",
                "WWW",
                "WWW_PTR",
                "WWW_CNAME",
                "Mail_A",
                "Mail_MX",
                "Mail_MX_Domain",
                "Mail_Suffix",
                "Mail_SPF",
                "Mail_DMARC",
                "Mail_PTR",
                "Create Date",
                "Refresh Date",
            ]
            result = dict(zip(dnskeys, dns))
            date = await get_create_date(domain)
            datedict = {"Create Date": date}
            result.update(datedict)
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


def load_data(input):
    data = asyncio.run(main(input))
    return data


@st.cache_data()
def www_image(url):
    image = capture_screenshot(url)
    return image


def style_df(df):
    df = df.style.hide(axis="columns", names=False).set_properties(
        **{"text-align": "left"}
    )
    return df


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
df_domain = df[df.index.isin(["Domain", "Suffix", "Create Date", "NS", "A", "CNAME"])]
df_email = df[df.index.isin(["Domain", "MX", "MX_Domain", "MX_Suffix", "SPF", "DMARC"])]
df_mail = df[
    df.index.isin(
        [
            "Domain",
            "Mail_A",
            "Mail_MX",
            "Mail_MX_Domain",
            "Mail_Suffix",
            "Mail_SPF",
            "Mail_DMARC",
            "Mail_PTR",
        ]
    )
]
df_mail.at["Domain", 0] = "mail." + input
df_website = df[df.index.isin(["Domain", "WWW", "WWW_PTR", "WWW_CNAME", "Parked"])]
df_website.at["Domain", 0] = "www." + input
df_description = df[df.index.isin(["Title", "Description", "Category", "Language"])]
df_domain_style = style_df(df_domain)
df_email_style = style_df(df_email)
df_mail_style = style_df(df_mail)
df_website_style = style_df(df_website)
df_description_style = style_df(df_description)
df_translation_style = style_df(
    df[df.index.isin(["Title", "Description", "Category", "Language", "Translation"])]
)


image = www_image(input)
col1, col2, col3 = st.columns(3)
with col1:
    st.subheader("Domain Info")
    st.write(df_domain_style.to_html(), unsafe_allow_html=True)
with col2:
    st.subheader("Email Info")
    st.write(df_email_style.to_html(), unsafe_allow_html=True)
with col3:
    st.subheader("Mail Info")
    st.write(df_mail_style.to_html(), unsafe_allow_html=True)
with st.container():
    st.subheader("Website Info")
    (
        col1,
        col2,
    ) = st.columns(2)
    with col1:
        st.write(df_website_style.to_html(), unsafe_allow_html=True)
    with col2:
        st.image(image, caption="Website Screenshot")
        st.markdown(f'{url} <a href="{url}">Click to open</a>', unsafe_allow_html=True)

    if data["Language"] != "en":
        st.write("Translated Text")
        st.write(df_translation_style.to_html(), unsafe_allow_html=True)
    else:
        st.write(df_description_style.to_html(), unsafe_allow_html=True)
