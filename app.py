# main.py
import os
import base64
from flask import Flask, render_template, Response, redirect, request, session, abort, url_for
import mysql.connector
import psycopg2
import hashlib
import shutil
from datetime import datetime
from datetime import date
import datetime
import json
import math
import random
from random import randint
from werkzeug.utils import secure_filename
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import csv
from PIL import Image
import stepic
import urllib.parse
from urllib.request import urlopen
import webbrowser
from Crypto import Random
from Crypto.Cipher import AES

mydb = psycopg2.connect(
    dbname="crop_insurance_sql",
    user="crop_insurance_sql_user",
    password="5EHUihWGBQ9771bziRAbgLuUF6zmRSZ1",
    host="dpg-d12k28buibrs73fa0vn0-a.oregon-postgres.render.com",
    port="5432"
)
cursor = mydb.cursor()
app = Flask(__name__)
##session key
app.secret_key = 'Ac989bmSnHPr_IVW8qh0QA'

UPLOAD_FOLDER = 'static/upload'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
#####
#######
class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]
####

@app.route('/', methods=['GET', 'POST'])
def index():
    msg=""
    cursor = mydb.cursor()
    cursor.execute("SELECT count(*) FROM ci_farmer")
    account = cursor.fetchone()[0]
    if account==0:
        ff=open("static/key.txt","w")
        ff.write("1")
        ff.close()
        ff=open("static/cropchain.json","w")
        ff.write("")
        ff.close()
        ff=open("static/assets/js/d1.txt","w")
        ff.write("")
        ff.close()



    return render_template('web/index.html',msg=msg)

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ""

    if request.method == 'POST':
        uname = request.form['uname']
        pwd = request.form['pass']

        cursor = mydb.cursor()
        cursor.execute('SELECT * FROM ci_farmer WHERE username = %s AND password = %s', (uname, pwd))
        account = cursor.fetchone()
        cursor.close()

        if account:
            session['username'] = uname
            return redirect(url_for('userhome'))  # <- must match route function name
        else:
            msg = 'Incorrect username/password!'
    return render_template('web/login.html', msg=msg)


@app.route('/login_admin', methods=['GET', 'POST'])
def login_admin():
    msg = ""

    if request.method == 'POST':
        uname = request.form['uname']
        pwd = request.form['pass']

        cursor = mydb.cursor()
        cursor.execute('SELECT * FROM ci_admin WHERE username = %s AND password = %s', (uname, pwd))
        account = cursor.fetchone()
        cursor.close()

        if account:
            session['username'] = uname
            return redirect(url_for('admin'))  # <- must match route function name
        else:
            msg = 'Incorrect username/password!'
    return render_template('web/login_admin.html', msg=msg)

@app.route('/login_company', methods=['GET', 'POST'])
def login_company():
    msg = ""

    if request.method == 'POST':
        uname = request.form['uname']
        pwd = request.form['pass']
        
        cursor = mydb.cursor()
        cursor.execute('SELECT * FROM ci_company WHERE username = %s AND password = %s AND approve_status = 1', (uname, pwd))
        account = cursor.fetchone()
        
        if account:
            session['username'] = uname
            return redirect(url_for('ins_home'))  # Remove '.html' from endpoint name
        else:
            msg = 'Incorrect username or password!'
    
    return render_template('web/login_company.html', msg=msg)



###
#Blockchain
class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()

        # Create the genesis block
        self.new_block(previous_hash='1', proof=100)

    def register_node(self, address):
        """
        Add a new node to the list of nodes

        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')


    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid

        :param chain: A blockchain
        :return: True if valid, False if not
        """

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: True if our chain was replaced, False if not
        """

        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

    def new_block(self, proof, previous_hash):
        """
        Create a new Block in the Blockchain

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount):
        """
        Creates a new transaction to go into the next mined Block

        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param amount: Amount
        :return: The index of the Block that will hold this transaction
        """
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })

        return self.last_block['index'] + 1

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block

        :param block: Block
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        """
        Simple Proof of Work Algorithm:

         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous proof, and p' is the new proof
         
        :param last_block: <dict> last Block
        :return: <int>
        """

        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        """
        Validates the Proof

        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.

        """

        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)

    # We must receive a reward for finding the proof.
    # The sender is "0" to signify that this node has mined a new coin.
    blockchain.new_transaction(
        sender="0",
        recipient=node_identifier,
        amount=1,
    )

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


def new_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['sender', 'recipient', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new Transaction
    index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'])

    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201

def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200



def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201

def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200

def cropchain(uid,uname,bcdata,utype):
    ############

    now = datetime.datetime.now()
    yr=now.strftime("%Y")
    mon=now.strftime("%m")
    rdate=now.strftime("%d-%m-%Y")
    rtime=now.strftime("%H:%M:%S")
    
    ff=open("static/key.txt","r")
    k=ff.read()
    ff.close()
    
    #bcdata="CID:"+uname+",Time:"+val1+",Unit:"+val2
    dtime=rdate+","+rtime

    ky=uname
    obj=AESCipher(ky)

    
    benc=obj.encrypt(bcdata)
    benc1=benc.decode("utf-8")

    ff1=open("static/assets/js/d1.txt","r")
    bc1=ff1.read()
    ff1.close()
    
    px=""
    if k=="1":
        px=""
        result = hashlib.md5(bcdata.encode())
        key=result.hexdigest()
        print(key)
        v=k+"##"+key+"##"+bcdata+"##"+dtime

        ff1=open("static/assets/js/d1.txt","w")
        ff1.write(v)
        ff1.close()
        
        dictionary = {
            "ID": "1",
            "Pre-hash": "00000000000000000000000000000000",
            "Hash": key,
            "utype": utype,
            "Date/Time": dtime
        }

        k1=int(k)
        k2=k1+1
        k3=str(k2)
        ff1=open("static/key.txt","w")
        ff1.write(k3)
        ff1.close()

        ff1=open("static/prehash.txt","w")
        ff1.write(key)
        ff1.close()
        
    else:
        px=","
        pre_k=""
        k1=int(k)
        k2=k1-1
        k4=str(k2)

        ff1=open("static/prehash.txt","r")
        pre_hash=ff1.read()
        ff1.close()
        
        g1=bc1.split("#|")
        for g2 in g1:
            g3=g2.split("##")
            if k4==g3[0]:
                pre_k=g3[1]
                break

        
        result = hashlib.md5(bcdata.encode())
        key=result.hexdigest()
        

        v="#|"+k+"##"+key+"##"+bcdata+"##"+dtime

        k3=str(k2)
        ff1=open("static/key.txt","w")
        ff1.write(k3)
        ff1.close()

        ff1=open("static/assets/js/d1.txt","a")
        ff1.write(v)
        ff1.close()

        
        
        dictionary = {
            "ID": k,
            "Pre-hash": pre_hash,
            "Hash": key,
            "utype:": utype,
            "Date/Time": dtime
        }
        k21=int(k)+1
        k3=str(k21)
        ff1=open("static/key.txt","w")
        ff1.write(k3)
        ff1.close()

        ff1=open("static/prehash.txt","w")
        ff1.write(key)
        ff1.close()

    m=""
    if k=="1":
        m="w"
    else:
        m="a"
    # Serializing json
    
    json_object = json.dumps(dictionary, indent=4)
     
    # Writing to sample.json
    with open("static/cropchain.json", m) as outfile:
        outfile.write(json_object)
    ##########
        

@app.route('/reg1', methods=['GET', 'POST'])
def reg1():
    msg=""
    aid=""
    mess=""
    mobile=""
    mycursor = mydb.cursor()

    if request.method=='POST':
        aadhar=request.form['aadhar']
        mycursor.execute('SELECT count(*) FROM ci_aadhar WHERE aadhar = %s ', (aadhar,))
        cnt = mycursor.fetchone()[0]
        if cnt>0:
            mycursor.execute('SELECT * FROM ci_aadhar WHERE aadhar = %s ', (aadhar,))
            data = mycursor.fetchone()
            mobile=str(data[2])
            aid=str(data[0])
            rn=randint(1000,9999)
            otp=str(rn)
            mycursor.execute("update ci_aadhar set otp=%s where aadhar=%s",(otp,aadhar))
            mydb.commit()
            mess="OTP: "+otp
            msg="ok"
        else:
            msg="fail"

    return render_template('web/reg1.html',msg=msg,mess=mess,mobile=mobile,aid=aid)

@app.route('/reg2', methods=['GET', 'POST'])
def reg2():
    msg=""
    aid=request.args.get("aid")
    
    mycursor = mydb.cursor()

    if request.method=='POST':
        otp=request.form['otp']
        mycursor.execute('SELECT count(*) FROM ci_aadhar WHERE id = %s && otp=%s', (aid,otp))
        cnt = mycursor.fetchone()[0]
        if cnt>0:
            
            msg="ok"
        else:
            msg="fail"

    return render_template('web/reg2.html',msg=msg,aid=aid)

@app.route('/reg3', methods=['GET', 'POST'])
def reg3():
    msg=""
    cid=""
    aid=request.args.get("aid")
    cid=""

    mycursor = mydb.cursor()

    if request.method=='POST':
        card=request.form['card']
        mycursor.execute('SELECT count(*) FROM ci_farmercard WHERE farmercard = %s ', (card,))
        cnt = mycursor.fetchone()[0]
        if cnt>0:
            mycursor.execute('SELECT * FROM ci_farmercard WHERE farmercard = %s ', (card,))
            dd = mycursor.fetchone()
            cid=str(dd[0])
            msg="ok"
        else:
            msg="fail"

    return render_template('web/reg3.html',msg=msg,aid=aid,cid=cid)

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg=""
    mycursor = mydb.cursor()
    aid=request.args.get("aid")
    cid=request.args.get("cid")

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
            
    mycursor.execute('SELECT * FROM ci_aadhar WHERE id = %s ', (aid,))
    adata = mycursor.fetchone()
    aadhar=adata[3]
    mycursor.execute('SELECT * FROM ci_farmercard WHERE id = %s ', (cid,))
    cdata = mycursor.fetchone()
    card=cdata[2]
            
    if request.method=='POST':
        name=request.form['name']
        last_name=request.form['last_name']
        mobile=request.form['mobile']
        email=request.form['email']
        address=request.form['address']
        district=request.form['district']
        uname=request.form['uname']
        pass1=request.form['pass']

        ky=uname
        obj=AESCipher(ky)
    
        mycursor.execute('SELECT count(*) FROM ci_farmer WHERE username = %s ', (uname,))
        cnt = mycursor.fetchone()[0]
        if cnt==0:
            mycursor.execute("SELECT max(id)+1 FROM ci_farmer")
            maxid = mycursor.fetchone()[0]
            if maxid is None:
                maxid=1

            bcdata="ID: "+str(maxid)+",Farmer :"+name+", Aadhar:"+aadhar+",Register Date: "+rdate+""
            
            cropchain(str(maxid),uname,bcdata,'Farmer')
            
            sql = "INSERT INTO ci_farmer(id,name,last_name,mobile,email,address,district,aadhar,farmercard,username,password,reg_date) VALUES (%s,%s,%s,%s, %s, %s, %s, %s, %s,%s, %s, %s)"
            val = (maxid,name,last_name,mobile,email,address,district,aadhar,card,uname,pass1,rdate)
            mycursor.execute(sql, val)
            mydb.commit()            
            
            msg="success"
        else:
            msg='fail'
    return render_template('web/register.html',msg=msg)

from flask import request, redirect, url_for, render_template, flash
from werkzeug.utils import secure_filename
import os
import datetime

@app.route('/reg_company', methods=['GET', 'POST'])
def reg_company():
    msg = ""
    mycursor = mydb.cursor()

    now = datetime.datetime.now()
    rdate = now.strftime("%d-%m-%Y")

    if request.method == 'POST':
        try:
            company = request.form['company']
            name = request.form['name']
            mobile = request.form['mobile']
            email = request.form['email']
            address = request.form['address']
            district = request.form['district']
            company_code = request.form['company_code']
            uname = request.form['uname']
            pass1 = request.form['pass']

            # Username check
            mycursor.execute("SELECT count(*) FROM ci_company WHERE username = %s", (uname,))
            cnt = mycursor.fetchone()[0]
            if cnt == 0:
                mycursor.execute("SELECT max(id)+1 FROM ci_company")
                maxid = mycursor.fetchone()[0]
                if maxid is None:
                    maxid = 1

                # File Upload
                file = request.files.get('file')
                filename = ""
                if file and file.filename != "":
                    fname = secure_filename(file.filename)
                    filename = "P" + str(maxid) + "_" + fname
                    file.save(os.path.join("static/upload", filename))
                else:
                    flash("No selected file")
                    return redirect(request.url)

                # Blockchain logging (if cropchain is defined)
                bcdata = f"ID: {maxid},Company: {name}, Code: {company_code},Register Date: {rdate}"
                cropchain(str(maxid), uname, bcdata, 'Company')

                sql = """
                INSERT INTO ci_company (id, company, name, mobile, email, address, district, company_code, license_proof, username, password, register_date)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                val = (maxid, company, name, mobile, email, address, district, company_code, filename, uname, pass1, rdate)
                mycursor.execute(sql, val)
                mydb.commit()

                msg = "success"
            else:
                msg = "fail"
        except Exception as e:
            print("ERROR during sign-up:", e)
            msg = "fail"
    
    return render_template('web/reg_company.html', msg=msg)
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    msg=""
    act = request.args.get('act')
    mess=""
    email=""
    uname=""
    if 'username' in session:
        uname = session['username']
   

    cursor1 = mydb.cursor()
    cursor1.execute("SELECT * FROM ci_company")
    data=cursor1.fetchall()
    

    if act=="ok":
        did = request.args.get('did')
        cursor1.execute("SELECT * FROM ci_company where id=%s",(did,))
        dr=cursor1.fetchone()
        email=dr[4]
        mess=""
        cursor1.execute('update ci_company set approve_status=1 where id=%s', (did,))
        mydb.commit()
        msg="ok"

    return render_template('admin.html',msg=msg,act=act,data=data,email=email,mess=mess)


@app.route('/admin_declare', methods=['GET', 'POST'])
def admin_declare():
    msg=""
    act = request.args.get('act')
    mess=""
    email=""
    data=[]
    cl=""
    district=""
    mdata=[]
    cd=[]
    s1=""
    s2=""
    aid="1"
    sdate=""
    edate=""
    uname=""
    if 'username' in session:
        uname = session['username']
   
    ff=open("static/district.txt","r")
    cd1=ff.read()
    ff.close()

    cd2=cd1.split("|")
    for cd3 in cd2:
        cd4=cd3.split(",")
        cd.append(cd4[0])
    

      
    #mycursor = mydb.cursor()
    '''mycursor.execute("SELECT count(*) FROM ci_apply")
    cnt=mycursor.fetchone()[0]
    if cnt>0:
        
        mycursor.execute("SELECT * FROM ci_apply")
        data=mycursor.fetchall()'''
    
    if request.method=='POST':
        cause_loss=request.form['cause_loss']
        district=request.form['district']
        sdate=request.form['sdate']
        edate=request.form['edate']


        #mycursor.execute("SELECT * FROM ci_apply where district=%s",(district,))
        #drow=mycursor.fetchone()
        #aid=drow[0]

        
        '''mycursor.execute("SELECT count(*) FROM ci_apply where district=%s && payout_st=0",(district,))
        cnt=mycursor.fetchone()[0]
        if cnt>0:        
            mycursor.execute("SELECT * FROM ci_apply where district=%s && payout_st=0",(district,))
            data3=mycursor.fetchall()
            for dr in data3:
                mycursor.execute("update ci_apply set payout_st=4 where id=%s",(dr[0],))
                mydb.commit()


        mycursor.execute("SELECT count(*) FROM ci_location where district=%s",(district,))
        scnt=mycursor.fetchone()[0]
        if scnt>0:
            mycursor.execute("SELECT * FROM ci_location where district=%s",(district,))
            srow=mycursor.fetchone()
            lat=srow[3]
            lon=srow[4]
            
        else:
            lat="10.783537"
            lon="78.775118"

        loc=lat+","+lon'''

    
        
        lat=""
        lon=""
        cd2=cd1.split("|")
        for cd3 in cd2:
            cd4=cd3.split(",")
            if cd4[0]==district:
                lat=cd4[1]
                lon=cd4[2]
                break
            
        loc=lat+","+lon
        cl=cause_loss
        s1="1"

        print(district)

        ddata=sdate+","+edate+","+cl+","+district+","+loc
        ff=open("static/ddata.txt","w")
        ff.write(ddata)
        ff.close()
        s1="1"
     

    return render_template('admin_declare.html',msg=msg,act=act,aid=aid,cd=cd,s1=s1)


@app.route('/admin_request', methods=['GET', 'POST'])
def admin_request():
    msg=""
    act = request.args.get('act')
    aid = request.args.get('aid')
    
    lat=""
    lon=""
    uname=""
    if 'username' in session:
        uname = session['username']

    
    
    ff=open("static/ddata.txt","r")
    dd=ff.read()
    ff.close()

    dd1=dd.split(",")
    sdate=dd1[0]
    edate=dd1[1]
    cl=dd1[2]
    district=dd1[3]
    loc=dd1[4]+","+dd1[5]
    

    ##
    #bcdata="ID: "+cid+", Weather Request by "+uname+", Farmer: "+farmer+", Location: "+loc+", Date: "+date1+" to "+date2+""
    #cropchain(cid,uname,bcdata,'Weather')
        
    shutil.copy("static/weather.csv","static/weather_data.csv")
    responsetext="https://weather.visualcrossing.com/VisualCrossingWebServices/rest/services/timeline/"+loc+"/"+sdate+"/"+edate+"?unitGroup=metric&include=days&key=8STCAMRSRTEZ77JA2XRP7FMNC&contentType=csv"

    cdata=[]
    data1 = pd.read_csv(responsetext, header=0)
    for ss in data1.values:
        dt=[]
        print(ss[0])
        
        with open("static/weather_data.csv",'a',newline='') as outfile:
            writer = csv.writer(outfile, quoting=csv.QUOTE_NONNUMERIC)
            writer.writerow(ss)

        cdata.append(dt)

    
    return render_template('admin_request.html',msg=msg,act=act,cl=cl)

@app.route('/admin_weather', methods=['GET', 'POST'])
def admin_weather():
    msg=""
    st=""
    act = request.args.get('act')
    cid = request.args.get('cid')
    cl = request.args.get('cl')
    data4=[]
    uname=""
    fn1=""
    fn2=""
    if 'username' in session:
        uname = session['username']

    #mycursor = mydb.cursor()
    '''mycursor.execute("SELECT * FROM ci_company where username=%s",(uname,))
    data=mycursor.fetchone()

    mycursor.execute("SELECT * FROM ci_scheme s,ci_claim a where s.id=a.sid && a.id=%s",(cid,))
    data3=mycursor.fetchone()
    aid=data3[36]'''

    data1 = pd.read_csv("static/weather_data.csv", header=0)
    r=0
    for ss in data1.values:
        dt=[]

        if ss[13]=="rain":
            if float(ss[12])>0 and float(ss[11])>0:
                r+=1
                
        dt.append(ss[1])
        dt.append(ss[2])
        dt.append(ss[3])
        dt.append(ss[4])
        dt.append(ss[9])
        dt.append(ss[29])
        dt.append(ss[30])
        dt.append(ss[31])
        data4.append(dt)

    
    if cl=="1" or cl=="2":
        if r>0:
            st="yes"
            ff=open("static/det.txt","r")
            d1=ff.read()
            ff.close()
            d2=d1.split(",")
            rn=randint(1,6)
            rn1=rn-1
            fn1=d2[rn1]
        else:
            st="no"
            #mycursor.execute("update ci_apply set payout_st=2 where id=%s",(aid,))
            #mydb.commit()
            
    elif cl=="3" or cl=="4":
        if r==0:
            st="yes"
            ff=open("static/det2.txt","r")
            d1=ff.read()
            ff.close()
            d2=d1.split(",")
            rn=randint(1,3)
            rn1=rn-1
            fn1=d2[rn1]
        else:
            st="no"
            #mycursor.execute("update ci_apply set payout_st=2 where id=%s",(aid,))
            #mydb.commit()

    ff=open("static/status.txt","w")
    ff.write(st)
    ff.close()
        
    
    return render_template('admin_weather.html',msg=msg,act=act,cid=cid,data4=data4,cl=cl,fn1=fn1,fn2=fn2)

@app.route('/admin_farmer', methods=['GET', 'POST'])
def admin_farmer():
    msg=""
    s1=""
    st=""
    act = request.args.get('act')
    sid = request.args.get('sid')
    data2=[]
    uname=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    #mycursor.execute("SELECT * FROM ci_company where username=%s",(uname,))
    #data=mycursor.fetchone()

    mycursor.execute("SELECT count(*) FROM ci_scheme s,ci_apply a where s.id=a.sid && a.payout_st=0")
    cnt2=mycursor.fetchone()[0]
    if cnt2>0:
        st="1"
        mycursor.execute("SELECT * FROM ci_scheme s,ci_apply a where s.id=a.sid && a.payout_st=0")
        data2=mycursor.fetchall()

    if request.method=='POST':
        
        mycursor.execute("SELECT * FROM ci_apply where payout_st=0")
        drow=mycursor.fetchall()
        for ds in drow:

            bcdata="ID: "+str(ds[0])+",Auto Payout to Farmer:"+ds[5]+", District: "+ds[9] 
            cropchain(str(ds[0]),ds[1],bcdata,'Auto')
        
            mycursor.execute("update ci_apply set payout_st=5 where id=%s",(ds[0],))
            mydb.commit()
        s1="1"


        
    return render_template('admin_farmer.html',msg=msg,act=act,data2=data2,s1=s1,st=st)

@app.route('/ins_auto', methods=['GET', 'POST'])
def ins_auto():
    msg=""
    s1=""
    act = request.args.get('act')
    sid = request.args.get('sid')
    uname=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_company where username=%s",(uname,))
    data=mycursor.fetchone()
    
    mycursor.execute("SELECT * FROM ci_scheme s,ci_apply a where s.id=a.sid && a.payout_st=5")
    data2=mycursor.fetchall()

    if request.method=='POST':
        
        mycursor.execute("SELECT * FROM ci_apply where payout_st=5")
        drow=mycursor.fetchall()
        for ds in drow:

            #bcdata="ID: "+str(ds[0])+",Auto Payout to Farmer:"+ds[5]+", District: "+ds[9] 
            #cropchain(str(ds[0]),ds[1],bcdata,'Auto')
        
            mycursor.execute("update ci_apply set payout_st=3,payout=premium_amount where id=%s",(ds[0],))
            mydb.commit()
        s1="1"


        
    return render_template('ins_auto.html',msg=msg,act=act,data=data,data2=data2,s1=s1)

@app.route('/admin_payout', methods=['GET', 'POST'])
def admin_payout():
    msg=""
    act = request.args.get('act')
    mess=""
    email=""
    mdata=[]
    s1=""
    s2=""
    uname=""
    if 'username' in session:
        uname = session['username']
   

    cursor1 = mydb.cursor()
    cursor1.execute("SELECT count(*) FROM ci_apply")
    cnt=cursor1.fetchone()[0]

    

    return render_template('admin_payout.html',msg=msg,act=act)

@app.route('/admin_bc1', methods=['GET', 'POST'])
def admin_bc1():
    msg=""
    act = request.args.get('act')
    mess=""
    email=""
    mdata=[]
    data=[]
    data1=[]
    s1=""
    s2=""
    uname=""
    if 'username' in session:
        uname = session['username']

    if act=="1":
        ff=open("static/cropchain.json","r")
        fj=ff.read()
        ff.close()

        fjj=fj.split('}')

        nn=len(fjj)
        nn2=nn-2
        i=0
        fsn=""
        while i<nn-1:
            if i==nn2:
                fsn+=fjj[i]+"}"
            else:
                fsn+=fjj[i]+"},"
            i+=1
            
        #fjj1='},'.join(fjj)
        
        fj1="["+fsn+"]"
        

        #ff=open("static/crop.json","w")
        #ff.write(fj1)
        #ff.close()
        
        dataframe = pd.read_json("static/crop.json", orient='values')
        
        
        #for ss in dataframe.values:
            
        #    if ss[4]=="Farmer" or ss[5]=="Payment" or ss[5]=="Claim":
                
        #        data1.append(ss)
        ff=open("static/assets/js/d1.txt","r")
        ds=ff.read()
        ff.close()

        drow=ds.split("#|")
        
        i=0
        for dr in drow:
            
            dr1=dr.split("##")
            dt=[]
            if "Register" in dr1[2]:
                
                dt.append(dr1[0])
                dt.append(dr1[1])
                dt.append(dr1[2])
                dt.append(dr1[3])
                #dt.append(dr1[4])
                data1.append(dt)

    ################
    if act=="11":
        s1="1"
        ff=open("static/assets/js/d1.txt","r")
        ds=ff.read()
        ff.close()

        drow=ds.split("#|")
        
        i=0
        for dr in drow:
            
            dr1=dr.split("##")
            dt=[]
            if "Register" in dr1[2]:
                
                dt.append(dr1[0])
                dt.append(dr1[1])
                dt.append(dr1[2])
                dt.append(dr1[3])
                #dt.append(dr1[4])
                data1.append(dt)
    

    return render_template('admin_bc1.html',msg=msg,act=act,data=data,data1=data1,s1=s1)

@app.route('/admin_bc2', methods=['GET', 'POST'])
def admin_bc2():
    msg=""
    act = request.args.get('act')
    mess=""
    email=""
    mdata=[]
    data=[]
    data1=[]
    s1=""
    s2=""
    uname=""
    if 'username' in session:
        uname = session['username']

    if act=="1":
        ff=open("static/cropchain.json","r")
        fj=ff.read()
        ff.close()

        fjj=fj.split('}')

        nn=len(fjj)
        nn2=nn-2
        i=0
        fsn=""
        while i<nn-1:
            if i==nn2:
                fsn+=fjj[i]+"}"
            else:
                fsn+=fjj[i]+"},"
            i+=1
            
        #fjj1='},'.join(fjj)
        
        fj1="["+fsn+"]"
        

        #ff=open("static/crop.json","w")
        #ff.write(fj1)
        #ff.close()
        
        dataframe = pd.read_json("static/crop.json", orient='values')
        
        
        #for ss in dataframe.values:
            
        #    if ss[4]=="Farmer" or ss[5]=="Payment" or ss[5]=="Claim":
                
        #        data1.append(ss)
        ff=open("static/assets/js/d1.txt","r")
        ds=ff.read()
        ff.close()

        drow=ds.split("#|")
        
        i=0
        for dr in drow:
            
            dr1=dr.split("##")
            dt=[]
            if "claim" in dr1[2] or "Premium" in dr1[2] or "apply" in dr1[2]:
                
                dt.append(dr1[0])
                dt.append(dr1[1])
                dt.append(dr1[2])
                dt.append(dr1[3])
                #dt.append(dr1[4])
                data1.append(dt)

    ################
    if act=="11":
        s1="1"
        ff=open("static/assets/js/d1.txt","r")
        ds=ff.read()
        ff.close()

        drow=ds.split("#|")
        
        i=0
        for dr in drow:
            
            dr1=dr.split("##")
            dt=[]
            if "claim" in dr1[2] or "Premium" in dr1[2] or "apply" in dr1[2]:
                
                dt.append(dr1[0])
                dt.append(dr1[1])
                dt.append(dr1[2])
                dt.append(dr1[3])
                #dt.append(dr1[4])
                data1.append(dt)
    

    return render_template('admin_bc2.html',msg=msg,act=act,data=data,data1=data1,s1=s1)

@app.route('/admin_bc3', methods=['GET', 'POST'])
def admin_bc3():
    msg=""
    act = request.args.get('act')
    mess=""
    email=""
    mdata=[]
    data=[]
    data1=[]
    s1=""
    s2=""
    uname=""
    if 'username' in session:
        uname = session['username']

    if act=="1":
        ff=open("static/cropchain.json","r")
        fj=ff.read()
        ff.close()

        fjj=fj.split('}')

        nn=len(fjj)
        nn2=nn-2
        i=0
        fsn=""
        while i<nn-1:
            if i==nn2:
                fsn+=fjj[i]+"}"
            else:
                fsn+=fjj[i]+"},"
            i+=1
            
        #fjj1='},'.join(fjj)
        
        fj1="["+fsn+"]"
        

        #ff=open("static/crop.json","w")
        #ff.write(fj1)
        #ff.close()
        
        dataframe = pd.read_json("static/crop.json", orient='values')
        
        
        #for ss in dataframe.values:
            
        #    if ss[4]=="Farmer" or ss[5]=="Payment" or ss[5]=="Claim":
                
        #        data1.append(ss)
        ff=open("static/assets/js/d1.txt","r")
        ds=ff.read()
        ff.close()

        drow=ds.split("#|")
        
        i=0
        for dr in drow:
            
            dr1=dr.split("##")
            dt=[]
            if "Weather" in dr1[2]:
                
                dt.append(dr1[0])
                dt.append(dr1[1])
                dt.append(dr1[2])
                dt.append(dr1[3])
                #dt.append(dr1[4])
                data1.append(dt)

    ################
    if act=="11":
        s1="1"
        ff=open("static/assets/js/d1.txt","r")
        ds=ff.read()
        ff.close()

        drow=ds.split("#|")
        
        i=0
        for dr in drow:
            
            dr1=dr.split("##")
            dt=[]
            if "Weather" in dr1[2]:
                
                dt.append(dr1[0])
                dt.append(dr1[1])
                dt.append(dr1[2])
                dt.append(dr1[3])
                #dt.append(dr1[4])
                data1.append(dt)
    

    return render_template('admin_bc3.html',msg=msg,act=act,data=data,data1=data1,s1=s1)

@app.route('/admin_bc4', methods=['GET', 'POST'])
def admin_bc4():
    msg=""
    act = request.args.get('act')
    mess=""
    email=""
    mdata=[]
    data=[]
    data1=[]
    s1=""
    s2=""
    uname=""
    if 'username' in session:
        uname = session['username']

    if act=="1":
        ff=open("static/cropchain.json","r")
        fj=ff.read()
        ff.close()

        fjj=fj.split('}')

        nn=len(fjj)
        nn2=nn-2
        i=0
        fsn=""
        while i<nn-1:
            if i==nn2:
                fsn+=fjj[i]+"}"
            else:
                fsn+=fjj[i]+"},"
            i+=1
            
        #fjj1='},'.join(fjj)
        
        fj1="["+fsn+"]"
        

        #ff=open("static/crop.json","w")
        #ff.write(fj1)
        #ff.close()
        
        dataframe = pd.read_json("static/crop.json", orient='values')
        
        
        #for ss in dataframe.values:
            
        #    if ss[4]=="Farmer" or ss[5]=="Payment" or ss[5]=="Claim":
                
        #        data1.append(ss)
        ff=open("static/assets/js/d1.txt","r")
        ds=ff.read()
        ff.close()

        drow=ds.split("#|")
        
        i=0
        for dr in drow:
            
            dr1=dr.split("##")
            dt=[]
            if "Credited" in dr1[2] or "Auto" in dr1[2]:
                
                dt.append(dr1[0])
                dt.append(dr1[1])
                dt.append(dr1[2])
                dt.append(dr1[3])
                #dt.append(dr1[4])
                data1.append(dt)

    ################
    if act=="11":
        s1="1"
        ff=open("static/assets/js/d1.txt","r")
        ds=ff.read()
        ff.close()

        drow=ds.split("#|")
        
        i=0
        for dr in drow:
            
            dr1=dr.split("##")
            dt=[]
            if "Credited" in dr1[2] or "Auto" in dr1[2]:
                
                dt.append(dr1[0])
                dt.append(dr1[1])
                dt.append(dr1[2])
                dt.append(dr1[3])
                #dt.append(dr1[4])
                data1.append(dt)
    

    return render_template('admin_bc4.html',msg=msg,act=act,data=data,data1=data1,s1=s1)

@app.route('/admin_bc5', methods=['GET', 'POST'])
def admin_bc5():
    msg=""
    act = request.args.get('act')
    mess=""
    email=""
    mdata=[]
    data=[]
    data1=[]
    s1=""
    s2=""
    uname=""
    if 'username' in session:
        uname = session['username']

    if act=="1":
        ff=open("static/cropchain.json","r")
        fj=ff.read()
        ff.close()

        fjj=fj.split('}')

        nn=len(fjj)
        nn2=nn-2
        i=0
        fsn=""
        while i<nn-1:
            if i==nn2:
                fsn+=fjj[i]+"}"
            else:
                fsn+=fjj[i]+"},"
            i+=1
            
        #fjj1='},'.join(fjj)
        
        fj1="["+fsn+"]"
        

        #ff=open("static/crop.json","w")
        #ff.write(fj1)
        #ff.close()
        
        dataframe = pd.read_json("static/crop.json", orient='values')
        
        
        #for ss in dataframe.values:
            
        #    if ss[4]=="Farmer" or ss[5]=="Payment" or ss[5]=="Claim":
                
        #        data1.append(ss)
        ff=open("static/assets/js/d1.txt","r")
        ds=ff.read()
        ff.close()

        drow=ds.split("#|")
        
        i=0
        for dr in drow:
            
            dr1=dr.split("##")
            dt=[]
            if "rating" in dr1[2]:
                
                dt.append(dr1[0])
                dt.append(dr1[1])
                dt.append(dr1[2])
                dt.append(dr1[3])
                #dt.append(dr1[4])
                data1.append(dt)

    ################
    if act=="11":
        s1="1"
        ff=open("static/assets/js/d1.txt","r")
        ds=ff.read()
        ff.close()

        drow=ds.split("#|")
        
        i=0
        for dr in drow:
            
            dr1=dr.split("##")
            dt=[]
            if "rating" in dr1[2]:
                
                dt.append(dr1[0])
                dt.append(dr1[1])
                dt.append(dr1[2])
                dt.append(dr1[3])
                #dt.append(dr1[4])
                data1.append(dt)
    

    return render_template('admin_bc5.html',msg=msg,act=act,data=data,data1=data1,s1=s1)


@app.route('/ins_home', methods=['GET', 'POST'])
def ins_home():
    msg=""
    act = request.args.get('act')
    uname=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_company where username=%s",(uname,))
    data=mycursor.fetchone()
    
    mycursor.execute("SELECT * FROM ci_scheme where company=%s",(uname,))
    data2=mycursor.fetchall()

    
    return render_template('ins_home.html',msg=msg,act=act,data=data,data2=data2)

@app.route('/ins_payout', methods=['GET', 'POST'])
def ins_payout():
    msg=""
    act = request.args.get('act')
    sid = request.args.get('sid')
    uname=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_company where username=%s",(uname,))
    data=mycursor.fetchone()
    
    mycursor.execute("SELECT * FROM ci_scheme s,ci_apply a where s.id=a.sid && a.company=%s && s.id=%s",(uname,sid))
    data2=mycursor.fetchall()

    
    return render_template('ins_payout.html',msg=msg,act=act,data=data,data2=data2)

@app.route('/ins_apply', methods=['GET', 'POST'])
def ins_apply():
    msg=""
    act = request.args.get('act')
    sid = request.args.get('sid')
    uname=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_company where username=%s",(uname,))
    data=mycursor.fetchone()
    
    mycursor.execute("SELECT * FROM ci_scheme s,ci_apply a where s.id=a.sid && a.company=%s && s.id=%s",(uname,sid))
    data2=mycursor.fetchall()

    
    return render_template('ins_apply.html',msg=msg,act=act,data=data,data2=data2)

@app.route('/ins_view', methods=['GET', 'POST'])
def ins_view():
    msg=""
    act = request.args.get('act')
    aid = request.args.get('aid')
    mess=""
    email=""
    uname=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_company where username=%s",(uname,))
    data=mycursor.fetchone()
    
    mycursor.execute("SELECT * FROM ci_scheme s,ci_apply a where s.id=a.sid && a.company=%s && a.id=%s",(uname,aid))
    data3=mycursor.fetchone()
    un=data3[9]

    mycursor.execute("SELECT * FROM ci_farmer where username=%s",(un,))
    udata=mycursor.fetchone()
    email=udata[4]
    name=udata[1]

    '''if act=="yes":
        mess="Dear "+name+", your insurance application has accepted"
        mycursor.execute("update ci_apply set status=1 where id=%s",(did,))
        mydb.commit()'''


    if act=="no":

        bcdata="ID: "+aid+",Application Rejected, Farmer:"+un+", by "+uname+", Date: "+rdate+""
        cropchain(str(maxid),uname,bcdata,'Company')

        mess="Dear "+name+", your insurance application has rejected"
        mycursor.execute("update ci_apply set status=2 where id=%s",(aid,))
        mydb.commit()
        return redirect(url_for('ins_home'))
        

        
    return render_template('ins_view.html',msg=msg,act=act,data=data,data3=data3,aid=aid,mess=mess,email=email)

@app.route('/ins_approve', methods=['GET', 'POST'])
def ins_approve():
    msg=""
    act = request.args.get('act')
    aid = request.args.get('aid')
    uname=""
    mess=""
    email=""
    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
    
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_company where username=%s",(uname,))
    data=mycursor.fetchone()

    mycursor.execute("SELECT * FROM ci_apply where id=%s",(aid,))
    data4=mycursor.fetchone()
    un=data4[1]
    
    print(un)
    mycursor.execute("SELECT * FROM ci_farmer where username=%s",(un,))
    udata=mycursor.fetchone()
    email=udata[4]
    name=udata[1]

    if request.method=='POST':
        amount=request.form['amount']
        
        mess="Dear "+name+", your insurance application has accepted, Premium Amount Rs."+amount

        bcdata="ID: "+aid+",Application Approved, Premium Amount:"+amount+" Farmer:"+un+" by "+uname+", Date: "+rdate+""
        cropchain(aid,uname,bcdata,'Company')

        
        mycursor.execute("update ci_apply set premium_amount=%s,status=1 where id=%s",(amount,aid))
        mydb.commit()
        msg="ok"
    

    return render_template('ins_approve.html',msg=msg,act=act,data=data,aid=aid,mess=mess,email=email)    

@app.route('/ins_pay', methods=['GET', 'POST'])
def ins_pay():
    msg=""
    act = request.args.get('act')
    aid = request.args.get('aid')
    uname=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_company where username=%s",(uname,))
    data=mycursor.fetchone()
    
    mycursor.execute("SELECT * FROM ci_payment where aid=%s",(aid,))
    data2=mycursor.fetchall()

    
    return render_template('ins_pay.html',msg=msg,act=act,data=data,data2=data2)

@app.route('/add_scheme', methods=['GET', 'POST'])
def add_scheme():
    msg=""
    aid=request.args.get("aid")
    cid=request.args.get("cid")
    uname=""
    if 'username' in session:
        uname = session['username']
        
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_company where username=%s",(uname,))
    data=mycursor.fetchone()
    
    filename=""
    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")

            
    if request.method=='POST':
        scheme=request.form['scheme']
        season=request.form['season']
        crops=request.form['crops']
        premium=request.form['premium']
        details=request.form['details']
        
        
            
        mycursor.execute("SELECT max(id)+1 FROM ci_scheme")
        maxid = mycursor.fetchone()[0]
        if maxid is None:
            maxid=1

        bcdata="ID: "+str(maxid)+",Scheme :"+scheme+",by "+uname+", Register Date: "+rdate+""
        cropchain(str(maxid),uname,bcdata,'Scheme')

        '''file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file:
            fname = file.filename
            ff = secure_filename(fname)
            filename="S"+str(maxid)+ff
            
            file.save(os.path.join("static/upload", filename))'''
    
        sql = "INSERT INTO ci_scheme(id,company,scheme,season,crops,premium_rate,details,create_date) VALUES (%s,%s,%s,%s,%s, %s, %s,%s)"
        val = (maxid,uname,scheme,season,crops,premium,details,rdate)
        mycursor.execute(sql, val)
        mydb.commit()            
        
        msg="success"
        
    return render_template('add_scheme.html',msg=msg,data=data)


@app.route('/userhome', methods=['GET', 'POST'])
def userhome():
    msg=""
    act = request.args.get('act')
    uname=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_farmer where username=%s",(uname,))
    data=mycursor.fetchone()
    
    mycursor.execute("SELECT * FROM ci_company")
    data2=mycursor.fetchall()

    
    return render_template('userhome.html',msg=msg,act=act,data=data,data2=data2)




@app.route('/farmer_scheme', methods=['GET', 'POST'])
def farmer_scheme():
    msg=""
    act = request.args.get('act')
    cid=request.args.get("cid")
    uname=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_farmer where username=%s",(uname,))
    data=mycursor.fetchone()
    
    mycursor.execute("SELECT * FROM ci_company where id=%s",(cid,))
    data2=mycursor.fetchone()
    company=data2[9]

    mycursor.execute("SELECT * FROM ci_scheme where company=%s",(company,))
    data3=mycursor.fetchall()
    

    return render_template('farmer_scheme.html',msg=msg,act=act,data=data,data2=data2,data3=data3)


@app.route('/farmer_apply', methods=['GET', 'POST'])
def farmer_apply():
    msg=""
    act = request.args.get('act')
    sid=request.args.get("sid")
    uname=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_farmer where username=%s",(uname,))
    data=mycursor.fetchone()

    mycursor.execute("SELECT * FROM ci_scheme where id=%s",(sid,))
    data3=mycursor.fetchone()
    company=data3[1]
    cid=data3[1]
    
    mycursor.execute("SELECT * FROM ci_company where username=%s",(company,))
    data2=mycursor.fetchone()
    #company=data2[9]

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")

    if request.method=='POST':
        aadhar=request.form['aadhar']
        name=request.form['name']
        father=request.form['father']
        door=request.form['door']
        landmark=request.form['landmark']
        district=request.form['district']
        mandal=request.form['mandal']
        ward=request.form['ward']
        mobile=request.form['mobile']
        email=request.form['email']
        ration=request.form['ration']
        community=request.form['community']
        farmer_cat=request.form['farmer_cat']
        
        account=request.form['account']
        branch=request.form['branch']
        ifsc=request.form['ifsc']
        district2=request.form['district2']
        mandal2=request.form['mandal2']
        ward2=request.form['ward2']
        survey=request.form['survey']
        extent=request.form['extent']

        hectare=request.form['hectare']
        crop_name=request.form['crop_name']
        sow_date=request.form['sow_date']
        area_sown=request.form['area_sown']

        file1 = request.files['file1']
        file2 = request.files['file2']
        file3 = request.files['file3']
        file4 = request.files['file4']
        file5 = request.files['file5']

        mycursor.execute("SELECT max(id)+1 FROM ci_apply")
        maxid = mycursor.fetchone()[0]
        if maxid is None:
            maxid=1

        fn1=file1.filename
        fnn1="A"+str(maxid)+fn1
        file1.save(os.path.join("static/upload", fnn1))

        fn2=file2.filename
        fnn2="B"+str(maxid)+fn2
        file2.save(os.path.join("static/upload", fnn2))

        fn3=file3.filename
        fnn3="C"+str(maxid)+fn3
        file3.save(os.path.join("static/upload", fnn3))

        fn4=file4.filename
        fnn4="D"+str(maxid)+fn4
        file4.save(os.path.join("static/upload", fnn4))

        fn5=file5.filename
        fnn5="E"+str(maxid)+fn5
        file5.save(os.path.join("static/upload", fnn5))
        
        
                
        

        sql = "INSERT INTO ci_apply(id,farmer,sid,company,aadhar,name,father,door,landmark,district,mandal,ward,mobile,email,ration,community,farmer_cat,apply_date) VALUES (%s,%s,%s, %s, %s, %s,%s,%s,%s,%s,%s,%s, %s, %s, %s,%s,%s,%s)"
        val = (maxid,uname,sid,company,aadhar,name,father,door,landmark,district,mandal,ward,mobile,email,ration,community,farmer_cat,rdate)
        mycursor.execute(sql, val)
        mydb.commit()

        bcdata="ID: "+str(maxid)+",Scheme ID :"+sid+", apply by "+uname+", Company: "+company+", Apply Date: "+rdate+""
        cropchain(str(maxid),uname,bcdata,'Scheme')

        mycursor.execute("update ci_apply set account=%s,branch=%s,ifsc=%s,district2=%s,mandal2=%s,ward2=%s,survey=%s,extent=%s,hectare=%s where id=%s",(account,branch,ifsc,district2,mandal2,ward2,survey,extent,hectare,maxid))
        mydb.commit()

        mycursor.execute("update ci_apply set crop_name=%s,sow_date=%s,area_sown=%s where id=%s",(crop_name,sow_date,area_sown,maxid))
        mydb.commit()

        mycursor.execute("update ci_apply set land_doc=%s,proof_aadhar=%s,proof_address=%s,proof_income=%s,photo=%s where id=%s",(fnn1,fnn2,fnn3,fnn4,fnn5,maxid))
        mydb.commit()
        msg="success"
    
    #data2=data2
    return render_template('farmer_apply.html',msg=msg,act=act,data=data,data3=data3)

@app.route('/farmer_query', methods=['GET', 'POST'])
def farmer_query():
    msg=""
    act = request.args.get('act')
    company = request.args.get('company')
    uname=""
    if 'username' in session:
        uname = session['username']

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
    
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_farmer where username=%s",(uname,))
    data=mycursor.fetchone()
    
    mycursor.execute("SELECT * FROM ci_query where farmer=%s",(uname,))
    data2=mycursor.fetchall()

    if request.method=='POST':
        query=request.form['farmer_query']
        mycursor.execute("SELECT max(id)+1 FROM ci_query")
        maxid = mycursor.fetchone()[0]
        if maxid is None:
            maxid=1

        sql = "INSERT INTO ci_query(id,farmer,company,farmer_query,reply,rdate) VALUES (%s,%s,%s, %s, %s, %s)"
        val = (maxid,uname,company,query,'',rdate)
        mycursor.execute(sql, val)
        mydb.commit()
        msg="success"
        
    
    return render_template('farmer_query.html',msg=msg,act=act,data=data,data2=data2)

@app.route('/ins_query', methods=['GET', 'POST'])
def ins_query():
    msg=""
    act = request.args.get('act')
    uname=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_company where username=%s",(uname,))
    data=mycursor.fetchone()
    
    mycursor.execute("SELECT * FROM ci_query where company=%s",(uname,))
    data2=mycursor.fetchall()

    
    return render_template('ins_query.html',msg=msg,act=act,data=data,data2=data2)

@app.route('/ins_reply', methods=['GET', 'POST'])
def ins_reply():
    msg=""
    act = request.args.get('act')
    qid = request.args.get('qid')
    uname=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_company where username=%s",(uname,))
    data=mycursor.fetchone()
    
    mycursor.execute("SELECT * FROM ci_query where company=%s",(uname,))
    data2=mycursor.fetchall()

    if request.method=='POST':
        reply=request.form['reply']
        mycursor.execute("update ci_query set reply=%s where id=%s",(reply,qid))
        mydb.commit()
        msg="ok"
    return render_template('ins_reply.html',msg=msg,act=act,data=data,data2=data2)

@app.route('/farmer_scheme2', methods=['GET', 'POST'])
def farmer_scheme2():
    msg=""
    act = request.args.get('act')
    uname=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_farmer where username=%s",(uname,))
    data=mycursor.fetchone()
    
    mycursor.execute("SELECT * FROM ci_company")
    data2=mycursor.fetchall()

    mycursor.execute("SELECT * FROM ci_scheme s,ci_apply a where s.id=a.sid && a.farmer=%s",(uname,))
    data3=mycursor.fetchall()

    
    return render_template('farmer_scheme2.html',msg=msg,act=act,data=data,data3=data3)

@app.route('/farmer_view', methods=['GET', 'POST'])
def farmer_view():
    msg=""
    act = request.args.get('act')
    aid=request.args.get("aid")

    uname=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_farmer where username=%s",(uname,))
    data=mycursor.fetchone()
    
    mycursor.execute("SELECT * FROM ci_company")
    data2=mycursor.fetchall()

    mycursor.execute("SELECT * FROM ci_scheme s,ci_apply a where s.id=a.sid && a.farmer=%s && a.id=%s",(uname,aid))
    data3=mycursor.fetchone()

    
    return render_template('farmer_view.html',msg=msg,act=act,data=data,data3=data3)

@app.route('/farmer_pay', methods=['GET', 'POST'])
def farmer_pay():
    msg=""
    act = request.args.get('act')
    uname=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_farmer where username=%s",(uname,))
    data=mycursor.fetchone()
    
    mycursor.execute("SELECT * FROM ci_company")
    data2=mycursor.fetchall()

    mycursor.execute("SELECT * FROM ci_scheme s,ci_apply a where s.id=a.sid && a.farmer=%s && a.status=1",(uname,))
    data3=mycursor.fetchall()

    
    return render_template('farmer_pay.html',msg=msg,act=act,data=data,data3=data3)

@app.route('/farmer_pay1', methods=['GET', 'POST'])
def farmer_pay1():
    msg=""
    act = request.args.get('act')
    aid=request.args.get("aid")
    pid=""
    uname=""
    mess=""
    mobile=""
    name=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_farmer where username=%s",(uname,))
    data=mycursor.fetchone()
    name=data[1]
    mobile=data[3]

    mycursor.execute("SELECT * FROM ci_scheme s,ci_apply a where s.id=a.sid && a.id=%s",(aid,))
    data3=mycursor.fetchone()
    sid=data3[0]
    company=data3[1]
    rate=float(data3[5])
    amt=float(data3[44])

    amt1=(rate/100)*amt
    amt2=round(amt1,2)

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")

    if request.method=='POST':
        amount=request.form['amount']
        star=request.form['star']
        pdate=request.form['pdate']

        otp=randint(1000,9999)
        mycursor.execute("update ci_apply set otp=%s where id=%s",(otp,aid))
        mydb.commit()

        mycursor.execute("SELECT max(id)+1 FROM ci_payment")
        maxid = mycursor.fetchone()[0]
        if maxid is None:
            maxid=1

        pid=str(maxid)
        mess="OTP: "+str(otp)
        if int(star)>=4:
            bcdata="ID: "+str(maxid)+",rating by "+uname+", Company: "+company+", Rating: "+str(star)+", "+rdate+""
            cropchain(str(maxid),uname,bcdata,'Scheme')

        sql = "INSERT INTO ci_payment(id,company,farmer,sid,aid,amount,pdate,pay_st,star) VALUES (%s,%s,%s,%s,%s, %s,%s,%s,%s)"
        val = (maxid,company,uname,sid,aid,amount,pdate,'0',star)
        mycursor.execute(sql, val)
        mydb.commit()  
        
        msg="ok"
    
    return render_template('farmer_pay1.html',msg=msg,act=act,data=data,aid=aid,data3=data3,amt2=amt2,pid=pid,mess=mess,mobile=mobile,name=name)

@app.route('/farmer_pay2', methods=['GET', 'POST'])
def farmer_pay2():
    msg=""
    act = request.args.get('act')
    aid=request.args.get("aid")
    pid=request.args.get("pid")
    uname=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_farmer where username=%s",(uname,))
    data=mycursor.fetchone()
    
    mycursor.execute("SELECT * FROM ci_payment where id=%s",(pid,))
    data2=mycursor.fetchone()
    pdate=data2[6]

    mycursor.execute("SELECT * FROM ci_scheme s,ci_apply a where s.id=a.sid && a.id=%s",(aid,))
    data3=mycursor.fetchone()
    sid=data3[0]
    otp=data3[46]
    company=data3[1]
    rate=float(data3[5])
    amt=float(data3[44])

    amt1=(rate/100)*amt
    amt2=round(amt1,2)
    

    if request.method=='POST':
        skey=request.form['otp']
        if otp==skey:
            bcdata="ID: "+pid+",Apply ID :"+aid+",Amount: Rs."+str(amt2)+" Pay by "+uname+", Company: "+company+", Pay Date: "+pdate+""
            cropchain(pid,uname,bcdata,'Payment')
        
            mycursor.execute("update ci_payment set pay_st=1 where id=%s",(pid,))
            mydb.commit()
            msg="ok"
        else:
            msg="fail"
        
      
    
    return render_template('farmer_pay2.html',msg=msg,act=act,data=data,aid=aid,data3=data3,amt2=amt2)

@app.route('/farmer_payhistory', methods=['GET', 'POST'])
def farmer_payhistory():
    msg=""
    act = request.args.get('act')
    aid=request.args.get("aid")

    uname=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_farmer where username=%s",(uname,))
    data=mycursor.fetchone()
    
    mycursor.execute("SELECT * FROM ci_payment where aid=%s",(aid,))
    data2=mycursor.fetchall()

      
    
    return render_template('farmer_payhistory.html',msg=msg,act=act,data=data,data2=data2)


@app.route('/farmer_claim', methods=['GET', 'POST'])
def farmer_claim():
    msg=""
    act = request.args.get('act')
    aid=request.args.get("aid")
    uname=""
    lat=""
    lon=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_farmer where username=%s",(uname,))
    data=mycursor.fetchone()

    mycursor.execute("SELECT * FROM ci_apply where id=%s",(aid,))
    data2=mycursor.fetchone()
    sid=data2[2]
    
    
    mycursor.execute("SELECT * FROM ci_scheme where id=%s",(sid,))
    data3=mycursor.fetchone()
    company=data3[1]
    

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")

    if request.method=='POST':
        aadhar=request.form['aadhar']
        name=request.form['name']
        father=request.form['father']
        address=request.form['address']
        district=request.form['district']
        mandal=request.form['mandal']
        ward=request.form['ward']
        mobile=request.form['mobile']
        email=request.form['email']
        community=request.form['community']
        
        bank=request.form['bank']
        account=request.form['account']
        branch=request.form['branch']
        ifsc=request.form['ifsc']
        account_type=request.form['account_type']
        
        loss_date=request.form['loss_date']
        loss_date2=request.form['loss_date2']
        total_area=request.form['total_area']
        crop_loss=request.form['crop_loss']
        cause_loss=request.form['cause_loss']

      
        mycursor.execute("SELECT max(id)+1 FROM ci_claim")
        maxid = mycursor.fetchone()[0]
        if maxid is None:
            maxid=1

        file1 = request.files['file1']
        file2 = request.files['file2']
        
        fn1=file1.filename
        fnn1="F"+str(maxid)+fn1
        file1.save(os.path.join("static/upload", fnn1))

        fn2=file2.filename
        fnn2="G"+str(maxid)+fn2
        file2.save(os.path.join("static/upload", fnn2))

        area="%"+ward+"%"
        mycursor.execute("SELECT count(*) FROM ci_location where area like %s",(area,))
        scnt=mycursor.fetchone()[0]
        if scnt>0:
            mycursor.execute("SELECT * FROM ci_location where area like %s",(area,))
            srow=mycursor.fetchone()
            lat=srow[3]
            lon=srow[4]
        else:
            lat="10.783537"
            lon="78.775118"

        sql = "INSERT INTO ci_claim(id,farmer,sid,company,aadhar,name,father,address,district,mandal,ward,mobile,email,community,claim_date) VALUES (%s,%s,%s, %s, %s, %s,%s,%s,%s,%s,%s,%s, %s, %s, %s)"
        val = (maxid,uname,sid,company,aadhar,name,father,address,district,mandal,ward,mobile,email,community,rdate)
        mycursor.execute(sql, val)
        mydb.commit()

        bcdata="ID: "+str(maxid)+",Scheme ID :"+str(sid)+", claim by "+uname+", Company: "+company+",Loss area: "+str(crop_loss)+"/"+str(total_area)+" hectare, Claim Date: "+rdate+""
        cropchain(str(maxid),uname,bcdata,'Claim')

        mycursor.execute("update ci_claim set bank=%s,account=%s,branch=%s,ifsc=%s,account_type=%s where id=%s",(bank,account,branch,ifsc,account_type,maxid))
        mydb.commit()

        mycursor.execute("update ci_claim set loss_date=%s,loss_date2=%s,total_area=%s,crop_loss=%s,cause_loss=%s,proof1=%s,proof2=%s,aid=%s,lat=%s,lon=%s where id=%s",(loss_date,loss_date2,total_area,crop_loss,cause_loss,fnn1,fnn2,aid,lat,lon,maxid))
        mydb.commit()

        
        msg="success"
    

    return render_template('farmer_claim.html',msg=msg,act=act,data=data,data2=data2,data3=data3)

@app.route('/ins_claim', methods=['GET', 'POST'])
def ins_claim():
    msg=""
    act = request.args.get('act')
    uname=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_company where username=%s",(uname,))
    data=mycursor.fetchone()

    mycursor.execute("SELECT * FROM ci_scheme s,ci_claim a where s.id=a.sid && a.company=%s",(uname,))
    data3=mycursor.fetchall()

    
    return render_template('ins_claim.html',msg=msg,act=act,data=data,data3=data3)

@app.route('/ins_viewclaim', methods=['GET', 'POST'])
def ins_viewclaim():
    msg=""
    act = request.args.get('act')
    cid = request.args.get('cid')
    uname=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_company where username=%s",(uname,))
    data=mycursor.fetchone()

    mycursor.execute("SELECT * FROM ci_scheme s,ci_claim a where s.id=a.sid && a.id=%s",(cid,))
    data3=mycursor.fetchone()
    aid=data3[36]

    mycursor.execute("SELECT * FROM ci_scheme s,ci_apply a where s.id=a.sid && a.id=%s",(aid,))
    data4=mycursor.fetchone()
    
    return render_template('ins_viewclaim.html',msg=msg,act=act,data=data,data3=data3,cid=cid,data4=data4)

@app.route('/ins_request', methods=['GET', 'POST'])
def ins_request():
    msg=""
    act = request.args.get('act')
    cid = request.args.get('cid')
    uname=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_company where username=%s",(uname,))
    data=mycursor.fetchone()

    mycursor.execute("SELECT * FROM ci_scheme s,ci_claim a where s.id=a.sid && a.id=%s",(cid,))
    data3=mycursor.fetchone()
    farmer=data3[9]

    loc="10.783537,78.775118"
    #date1="2023-12-01"
    #date2="2023-12-05"
    date1=data3[27]
    date2=data3[28]

    print("dddd")
    print(date1)
    print(date2)
    ##
    bcdata="ID: "+cid+", Weather Request by "+uname+", Farmer: "+farmer+", Location: "+loc+", Date: "+date1+" to "+date2+""
    cropchain(cid,uname,bcdata,'Weather')
        
    shutil.copy("static/weather.csv","static/weather_data.csv")
    responsetext="https://weather.visualcrossing.com/VisualCrossingWebServices/rest/services/timeline/"+loc+"/"+date1+"/"+date2+"?unitGroup=metric&include=days&key=8STCAMRSRTEZ77JA2XRP7FMNC&contentType=csv"

    cdata=[]
    data1 = pd.read_csv(responsetext, header=0)
    for ss in data1.values:
        dt=[]
        print(ss[0])
        
        with open("static/weather_data.csv",'a',newline='') as outfile:
            writer = csv.writer(outfile, quoting=csv.QUOTE_NONNUMERIC)
            writer.writerow(ss)

        cdata.append(dt)

    
    return render_template('ins_request.html',msg=msg,act=act,data=data,data3=data3,cid=cid)

@app.route('/ins_weather', methods=['GET', 'POST'])
def ins_weather():
    msg=""
    st=""
    fn1=""
    act = request.args.get('act')
    cid = request.args.get('cid')
    data4=[]
    uname=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_company where username=%s",(uname,))
    data=mycursor.fetchone()

    mycursor.execute("SELECT * FROM ci_scheme s,ci_claim a where s.id=a.sid && a.id=%s",(cid,))
    data3=mycursor.fetchone()
    aid=data3[36]

    data1 = pd.read_csv("static/weather_data.csv", header=0)
    r=0
    for ss in data1.values:
        dt=[]

        if ss[13]=="rain":
            if float(ss[12])>0 and float(ss[11])>0:
                r+=1
                
        dt.append(ss[1])
        dt.append(ss[2])
        dt.append(ss[3])
        dt.append(ss[4])
        dt.append(ss[9])
        dt.append(ss[29])
        dt.append(ss[30])
        dt.append(ss[31])
        data4.append(dt)

    
    if data3[31]=="1" or data3[31]=="2":
        if r>0:
            st="yes"
            ff=open("static/det.txt","r")
            d1=ff.read()
            ff.close()
            d2=d1.split(",")
            rn=randint(1,6)
            rn1=rn-1
            fn1=d2[rn1]
        else:
            st="no"
            mycursor.execute("update ci_apply set payout_st=2 where id=%s",(aid,))
            mydb.commit()
            
    elif data3[31]=="3" or data3[31]=="4":
        if r==0:
            st="yes"
            ff=open("static/det2.txt","r")
            d1=ff.read()
            ff.close()
            d2=d1.split(",")
            rn=randint(1,3)
            rn1=rn-1
            fn1=d2[rn1]
        else:
            st="no"
            mycursor.execute("update ci_apply set payout_st=2 where id=%s",(aid,))
            mydb.commit()

    ff=open("static/status.txt","w")
    ff.write(st)
    ff.close()
        
    
    return render_template('ins_weather.html',msg=msg,act=act,data=data,data3=data3,cid=cid,data4=data4,fn1=fn1)


@app.route('/ins_claimprocess', methods=['GET', 'POST'])
def ins_claimprocess():
    msg=""
    act = request.args.get('act')
    cid = request.args.get('cid')
    data4=[]
    pay_amt=0
    amount=0
    st=""
    uname=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_company where username=%s",(uname,))
    data=mycursor.fetchone()

    ff=open("static/status.txt","r")
    st=ff.read()
    ff.close()

    mycursor.execute("SELECT * FROM ci_scheme s,ci_claim a where s.id=a.sid && a.id=%s",(cid,))
    data3=mycursor.fetchone()

    aid=data3[36]

    mycursor.execute("SELECT * FROM ci_scheme s,ci_apply a where s.id=a.sid && a.id=%s",(aid,))
    data4=mycursor.fetchone()

    amount=data4[44]
    tot=float(data3[29])
    crop_loss=float(data3[30])

    if tot==crop_loss:
        pay_amt=amount
    else:

        pa=(crop_loss/tot)*amount
        pay_amt=round(pa,2)
        
    
    if request.method=='POST':
        s=1
        mycursor.execute("update ci_apply set payout_st=1,payout=%s where id=%s",(pay_amt,aid))
        mydb.commit()

        if st=="yes":
            msg="payout"
            mycursor.execute("update ci_claim set status=1 where id=%s",(cid,))
            mydb.commit()
        else:
            mycursor.execute("update ci_claim set status=2 where id=%s",(cid,))
            mydb.commit()
            

        
        


        
    return render_template('ins_claimprocess.html',msg=msg,act=act,st=st,data=data,data3=data3,cid=cid,amount=amount,pay_amt=pay_amt)



@app.route('/ins_map', methods=['GET', 'POST'])
def ins_map():
    msg=""
    cid = request.args.get('cid')
    uname=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_company where username=%s",(uname,))
    data=mycursor.fetchone()
    

    mycursor.execute("SELECT * FROM ci_claim where id=%s",(cid,))
    data3=mycursor.fetchone()
    lat=data3[29]
    lon=data3[30]
    name=data3[5]
    area=data3[10]
    district=data3[8]

    return render_template('ins_map.html',msg=msg,cid=cid,data=data)


@app.route('/map', methods=['GET', 'POST'])
def map():
    msg=""
    cid = request.args.get('cid')

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_claim where id=%s",(cid,))
    data3=mycursor.fetchone()
    lat=data3[29]
    lon=data3[30]
    name=data3[5]
    area=data3[10]
    district=data3[8]
    return render_template('map.html',msg=msg,cid=cid,name=name,lat=lat,lon=lon,area=area,district=district)


@app.route('/ins_claimprocess1', methods=['GET', 'POST'])
def ins_claimprocess1():
    msg=""
    act = request.args.get('act')
    cid = request.args.get('cid')
    data4=[]
    pay_amt=0
    amount=0
    st=""
    uname=""
    if 'username' in session:
        uname = session['username']

    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_company where username=%s",(uname,))
    data=mycursor.fetchone()

  

    mycursor.execute("SELECT * FROM ci_scheme s,ci_claim a where s.id=a.sid && a.id=%s",(cid,))
    data3=mycursor.fetchone()

    aid=data3[36]

    mycursor.execute("SELECT * FROM ci_scheme s,ci_apply a where s.id=a.sid && a.id=%s",(aid,))
    data4=mycursor.fetchone()

    amount=data4[44]
    tot=float(data3[29])
    crop_loss=float(data3[30])

    if tot==crop_loss:
        pay_amt=amount
    else:

        pa=(crop_loss/tot)*amount
        pay_amt=round(pa,2)
        
    
    if request.method=='POST':
        s=1
        mycursor.execute("update ci_apply set payout_st=1,payout=%s where id=%s",(pay_amt,aid))
        mydb.commit()

        mycursor.execute("update ci_claim set status=1 where id=%s",(cid,))
        mydb.commit()

        
        msg="ok"


        
    return render_template('ins_claimprocess1.html',msg=msg,act=act,st=st,data=data,data3=data3,cid=cid,amount=amount,pay_amt=pay_amt)

@app.route('/ins_bank', methods=['GET', 'POST'])
def ins_bank():
    msg=""
    act = request.args.get('act')
    cid = request.args.get('cid')
    data4=[]
    pay_amt=0
    amount=0
    name=""
    mobile=""
    email=""
    mess=""
    st=""
    uname=""
    if 'username' in session:
        uname = session['username']

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
    
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM ci_company where username=%s",(uname,))
    data=mycursor.fetchone()

    ff=open("static/status.txt","r")
    st=ff.read()
    ff.close()

    mycursor.execute("SELECT * FROM ci_scheme s,ci_claim a where s.id=a.sid && a.id=%s",(cid,))
    data3=mycursor.fetchone()

    aid=data3[36]
    farmer=data3[9]

    mycursor.execute("SELECT * FROM ci_scheme s,ci_apply a where s.id=a.sid && a.id=%s",(aid,))
    data4=mycursor.fetchone()

    amount=data4[44]
    tot=float(data3[29])
    crop_loss=float(data3[30])

    if tot==crop_loss:
        pay_amt=amount
    else:

        pa=(crop_loss/tot)*amount
        pay_amt=round(pa,2)


    mycursor.execute("SELECT * FROM ci_farmer where username=%s",(farmer,))
    data5=mycursor.fetchone()
    name=data5[1]
    mobile=data5[3]
    email=data5[4]
    #mess="Insure Amount Credited, Rs."+str(pay_amt)
    mess="Dear "+name+", Insure Amount Credited, Rs."+str(pay_amt)
    if act=="2":

        bcdata="ID: "+str(aid)+",Farmer :"+farmer+", Insure Amount Credited, Rs. "+str(pay_amt)+", Company: "+uname+", Pay Date: "+rdate
        cropchain(str(aid),uname,bcdata,'Payout')
        
        
    return render_template('ins_bank.html',msg=msg,act=act,st=st,data=data,data3=data3,cid=cid,name=name,mobile=mobile,mess=mess,email=email)



@app.route('/logout')
def logout():
    # remove the username from the session if it is there
    session.pop('username', None)
    return redirect(url_for('index'))




if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
