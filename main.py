from OTXv2 import OTXv2
from app import App

otx = OTXv2("65c4b1a25b5896043ef4dfd0b38ea42a5910abac8f4fd19e79f83fda68965eeb")


def create_pulses(app_):
    pulses = otx.getall_iter()
    for pulse in pulses:
        app_.create_pulse(pulse)


if __name__ == '__main__':
    bolt_url = "bolt://localhost:7687"
    user = "neo4j"
    password = "1234"
    app = App(bolt_url, user, password)
    create_pulses(app)
    app.close()
