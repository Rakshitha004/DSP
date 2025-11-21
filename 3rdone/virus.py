import streamlit as st
import random, json, csv, io
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

# ----------------------------- Models -----------------------------

@dataclass
class Document:
    name: str
    content: str
    has_macro: bool = False
    macro_behavior: Optional[str] = None

@dataclass
class Email:
    sender: str
    recipient: str
    subject: str
    body: str
    attachment: Optional[Document] = None
    link: Optional[str] = None

@dataclass
class Node:
    id: str
    user: str
    compromised: bool = False
    compromise_vector: Optional[str] = None
    files: List[Document] = field(default_factory=list)
    mailbox: List[Email] = field(default_factory=list)
    detection_alerts: List[Dict] = field(default_factory=list)

    def receive_email(self, email: Email):
        self.mailbox.append(email)

# ----------------------------- Attack Simulation -----------------------------

class Attacker:
    def __init__(self, name: str = "attacker@example.com"):
        self.name = name

    def craft_phishing_email(self, target_user: str, lure: str = "invoice") -> Email:
        subj = f"{lure.title()} - Action Required"
        body = f"Hi {target_user},\nPlease see attached {lure}."
        doc = Document(
            name=f"{lure}_{random.randint(100,999)}.docm",
            content=f"Simulated {lure} content",
            has_macro=True,
            macro_behavior="exfiltrate_simulated_credentials"
        )
        return Email(sender=self.name, recipient=target_user, subject=subj, body=body, attachment=doc)

    def craft_malicious_link_email(self, target_user: str, domain="bad.example") -> Email:
        subj = "Security Alert - Verify Your Account"
        body = f"Dear {target_user}, verify here: http://{domain}/verify"
        return Email(sender=self.name, recipient=target_user, subject=subj, body=body, link=f"http://{domain}/verify")

# ----------------------------- Detection Modules -----------------------------

class SignatureDetector:
    KNOWN_SIGNATURES = ["exfiltrate_simulated_credentials","evil_macro","drop_ransom_note","keylogger_stub"]
    def scan_document(self, doc: Document) -> Optional[str]:
        if doc.macro_behavior in self.KNOWN_SIGNATURES:
            return f"signature:{doc.macro_behavior}"
        return None
    def scan_email(self, email: Email) -> Optional[str]:
        if email.attachment:
            return self.scan_document(email.attachment)
        if email.link and "bad.example" in email.link:
            return "signature:malicious-link"
        return None

class HeuristicDetector:
    def score_email(self, email: Email) -> Tuple[float,List[str]]:
        score, reasons = 0.0, []
        if "action required" in email.subject.lower():
            score += 0.3; reasons.append("suspicious-subject")
        if email.link:
            score += 0.3; reasons.append("contains-link")
            if "bad.example" in email.link:
                score += 0.5; reasons.append("known-bad-domain")
        if email.attachment:
            score += 0.25; reasons.append("attachment")
            if email.attachment.has_macro:
                score += 0.4; reasons.append("macro")
        return min(score,1.0), reasons

# ----------------------------- Simulator -----------------------------

class Simulator:
    def __init__(self,num_nodes=10,seed=None):
        self.nodes = {}
        self.attacker = Attacker()
        self.sig = SignatureDetector()
        self.heur = HeuristicDetector()
        self.time = 0
        if seed: random.seed(seed)
        for i in range(num_nodes):
            user = f"user{i+1}@example.com"
            self.nodes[f"node{i+1}"] = Node(id=f"node{i+1}", user=user)

    def simulate_phishing(self,targets,click_rate):
        events=[]
        for t in targets:
            node=self.nodes[t]
            email=self.attacker.craft_phishing_email(node.user)
            node.receive_email(email)
            events.append((t,"phish_sent",email.subject))
            sig=self.sig.scan_email(email); score,reasons=self.heur.score_email(email)
            if sig: node.detection_alerts.append({"time":self.time,"sig":sig})
            elif score>=0.7: node.detection_alerts.append({"time":self.time,"heur":reasons})
            if random.random()<click_rate:
                node.compromised=True; node.compromise_vector="macro"; events.append((t,"compromised","macro"))
        return events

    def simulate_links(self,targets,click_rate):
        events=[]
        for t in targets:
            node=self.nodes[t]
            email=self.attacker.craft_malicious_link_email(node.user)
            node.receive_email(email)
            events.append((t,"link_sent",email.link))
            sig=self.sig.scan_email(email); score,reasons=self.heur.score_email(email)
            if sig: node.detection_alerts.append({"time":self.time,"sig":sig})
            elif score>=0.7: node.detection_alerts.append({"time":self.time,"heur":reasons})
            if random.random()<click_rate:
                node.compromised=True; node.compromise_vector="drive_by"; events.append((t,"compromised","drive_by"))
        return events

    def propagate(self):
        events=[]
        compromised=[n for n in self.nodes.values() if n.compromised]
        for node in compromised:
            targets=[n for n in self.nodes.values() if not n.compromised]
            for target in random.sample(targets,min(1,len(targets))):
                target.compromised=True; target.compromise_vector="internal_propagation"
                events.append((node.id,"propagated",target.id))
        return events

    def summary(self):
        return {
            "time":self.time,
            "compromised":[n.id for n in self.nodes.values() if n.compromised],
            "alerts":{n.id:n.detection_alerts for n in self.nodes.values() if n.detection_alerts}
        }

# ----------------------------- Streamlit App -----------------------------

st.set_page_config(page_title="📧 Virus Simulation Lab",layout="wide")
st.title("📧 Email & Document Virus Simulator (Safe Educational Demo)")

nodes=st.sidebar.slider("Number of Nodes",5,30,12)
rounds=st.sidebar.slider("Simulation Rounds",1,10,4)
click_attach=st.sidebar.slider("Attachment Click Rate",0.0,1.0,0.3,0.05)
click_link=st.sidebar.slider("Link Click Rate",0.0,1.0,0.2,0.05)
seed=st.sidebar.number_input("Random Seed (0 = none)",0,9999,0)

if st.button("▶️ Run Simulation"):
    sim=Simulator(num_nodes=nodes,seed=(seed if seed>0 else None))
    log=[]
    for r in range(rounds):
        sim.time+=1
        st.subheader(f"Round {r+1}")
        t1=random.sample(list(sim.nodes.keys()),max(1,nodes//3))
        ev1=sim.simulate_phishing(t1,click_attach)
        for e in ev1: st.write(e); log.append((sim.time,e))
        t2=random.sample(list(sim.nodes.keys()),max(1,nodes//4))
        ev2=sim.simulate_links(t2,click_link)
        for e in ev2: st.write(e); log.append((sim.time,e))
        ev3=sim.propagate()
        for e in ev3: st.write(e); log.append((sim.time,e))
        st.json(sim.summary())

    st.subheader("Final Summary")
    st.json(sim.summary())

    # CSV download
    csv_buf=io.StringIO()
    writer=csv.writer(csv_buf); writer.writerow(["time","node","action","detail"])
    for t,e in log: writer.writerow([t]+list(e))
    st.download_button("Download Log CSV",csv_buf.getvalue(),"sim_log.csv","text/csv")



