from neo4j import GraphDatabase


class App:

    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def create_pulse(self, pulse):
        with self.driver.session() as session:
            session.write_transaction(self._create_pulse, pulse)
            print(f"Created or modified pulse with name: {pulse.get('name')}")

    def create_attack_item(self, item):
        with self.driver.session() as session:
            session.write_transaction(self._create_attack_item, item)

    @staticmethod
    def _create_attack_item(tx, item):
        match item["type"]:
            case "attack-pattern":
                query = App._create_attack_pattern(item)
                if item.get('kill_chain_phases'):
                    tx.run(query, kill_chain_phases=item['kill_chain_phases'])
                    return
            case "intrusion-set":
                return
            case "malware":
                return
            case "x-mitre-tactic":
                query = App._create_attack_tactic(item)
                tx.run(query, ext_ref=item['external_references'])
                return
            case "relationship":
                return
            case _:
                return

    @staticmethod
    def _create_attack_pattern(attack):
        query = (''.join((
            f"MERGE (a:Attack_pattern {{name: '{attack['name']}'}}) ",  # When 2 have same name? -> napr. "Accessibility Features" tam je 2krat
            f"SET a.description = '{attack['description']}'" if attack.get('description') else "",  # Problem s file paths -> napr. \u v stringu
            f"WITH a UNWIND {attack['x_mitre_data_sources']} as data_source "
            "MERGE (d:Data_source {name: data_source}) "
            "MERGE (a)-[:HAS_DATA_SOURCE]->(d) " if attack.get('x_mitre_data_sources') else "",
            f"WITH a UNWIND {attack['x_mitre_permissions_required']} as permission "
            "MERGE (perm:Permission {name: permission}) "
            "MERGE (a)-[:REQUIRES]->(perm) " if attack.get('x_mitre_permissions_required') else "",
            f"WITH a UNWIND {attack['x_mitre_platforms']} as platform "
            "MERGE (p:Platform {name: platform}) "
            "MERGE (a)-[:ON_PLATFORM]->(p) " if attack.get('x_mitre_platforms') else "",
            f"WITH a UNWIND $kill_chain_phases as phase "
            "CALL apoc.merge.node(['Kill_chain_phase'], {name: phase['phase_name']}) "
            "YIELD node "
            "MERGE (a)-[:HAS_PHASE]->(node)" if attack.get('kill_chain_phases') else "",
            "RETURN *"))  # Z ext ref ATT&CK, CAPEC a CVE
        )
        return query

    @staticmethod
    def _create_attack_tactic(tactic):
        query = (''.join((
            f"MERGE (t:Tactic {{name: '{tactic['name']}'}}) "
            f'SET t.description = "{tactic["description"]}" '
            f"WITH t UNWIND $ext_ref as ex_ref "
            "SET t.id = ex_ref['external_id'] "
            "RETURN *"))
        )
        return query

    @staticmethod
    def _create_pulse(tx, pulse):
        query = (''.join((
            "MERGE (u:User { name: $author_name }) "
            "MERGE (p:Pulse { id: $pulse_id}) ",
            f"SET p:{pulse['tlp']}, p.name = $pulse_name, p.description = $pulse_description, p.revision = $revision, ",
            "p.public = $public, p.references = $references "
            "MERGE (u)-[:CREATED {created: $created, modified: $modified}]->(p) ",
            "MERGE (adv:Adversary { name: $adversary}) "
            "MERGE (p)-[:HAS_ADVERSARY]->(adv) " if pulse['adversary'] else "",
            App._create_pulse_subquery("Tag", "HAS_TAG", pulse["tags"]),
            App._create_pulse_subquery("Malware_family", "IN_MALWARE_FAMILY", pulse["malware_families"]),
            App._create_pulse_subquery("Country", "TARGETS", pulse["targeted_countries"]),
            App._create_pulse_subquery("Industry", "CONCERNS", pulse["industries"]),
            App._create_attacks_subquery(pulse["attack_ids"]),
            "WITH p UNWIND $indicators as iItem "
            "CALL apoc.merge.node(['Indicator', iItem['type']], {id: iItem['id']}, {indicator: iItem['indicator'], "
            "content: iItem['content'], title: iItem['title'], description: iItem['description'], "
            "is_active: iItem['is_active'], expiration: iItem['expiration']}) "
            "YIELD node "
            "MERGE (p)-[:HAS_INDICATOR]->(node) "
            "WITH node, iItem "
            "CALL apoc.do.when("
            "iItem['role'] IS NOT NULL,"
            "'MERGE (role:Role {name: iItem[\"role\"]}) "
            "MERGE (node)-[:HAS_ROLE]->(role)',"
            "'',"
            "{iItem:iItem, node:node}) "
            "YIELD value "
            "RETURN *"))
        )
        tx.run(query, author_name=pulse['author_name'], pulse_id=pulse['id'], pulse_name=pulse['name'],
               pulse_description=pulse['description'], revision=pulse['revision'], public=pulse['public'],
               references=pulse['references'], adversary=pulse['adversary'],
               created=pulse['created'], modified=pulse['modified'], indicators=pulse['indicators']
               )

    @staticmethod
    def _create_pulse_subquery(node_type, relationship_name, arr, attribute_name="name"):
        if not arr:
            return ""
        else:
            return f"FOREACH (item in {arr} | " \
                   f"MERGE (t:{node_type} {{{attribute_name}: item}}) " \
                   f"MERGE (p)-[:{relationship_name}]->(t)) "

    @staticmethod
    def _create_attacks_subquery(attacks):
        if not attacks:
            return ""
        else:
            return f"WITH p " \
                   f"UNWIND {attacks} as item " \
                   f"MERGE (t:Attack {{id: item}}) " \
                   f"MERGE (p)-[:HAS_ATTACK]->(t) " \
                   f"WITH item, t, p " \
                   f"CALL apoc.do.when(" \
                   f"item CONTAINS '.'," \
                   f"'MERGE (t1:Attack {{id: split(item, \".\")[0]}}) " \
                   f"MERGE (t1)-[:PARENT]->(t)'," \
                   f"''," \
                   f"{{item:item, t:t}}) " \
                   f"YIELD value "
