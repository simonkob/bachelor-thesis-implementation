from neo4j import GraphDatabase
import re


class App:

    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def create_pulse(self, pulse):
        with self.driver.session() as session:
            session.write_transaction(self._create_pulse, pulse)
            print(f"Created or modified pulse with name: {pulse.get('name')}")

    def create_attack_item(self, item, json_objects_dict):
        with self.driver.session() as session:
            session.write_transaction(self._create_attack_item, item, json_objects_dict)

    @staticmethod
    def _create_attack_item(tx, item, json_objects_dict):
        if item.get("revoked"):
            return
        match item["type"]:
            case "attack-pattern":
                json_objects_dict.update({item.get("id"): item.get('external_references')[0]['external_id']})
                tx.run(App._create_attack_pattern(item), desc=item.get('description'),
                       kill_chain_phases=item.get('kill_chain_phases'))
                return
            case "intrusion-set":
                json_objects_dict.update({item.get("id"): item.get('external_references')[0]['external_id']})
                tx.run(App._create_attack_intrusion(item), ext_ref=item.get('external_references'),
                       desc=item.get('description'))
                return
            case "malware":
                json_objects_dict.update({item.get("id"): item.get('external_references')[0]['external_id']})
                tx.run(App._create_attack_malware(item), desc=item.get('description'))
                return
            case "x-mitre-tactic":
                json_objects_dict.update({item.get("id"): item.get('external_references')[0]['external_id']})
                tx.run(App._create_attack_tactic(item))
                return
            case "relationship":
                if App._get_type(item.get("source_ref")) in ("Malware", "Attack_pattern", "Intrusion_set") \
                        and App._get_type(item.get("target_ref")) in ("Malware", "Attack_pattern", "Intrusion_set"):
                    tx.run(App._create_attack_relationship(item, json_objects_dict))
                return
            case _:
                return

    @staticmethod
    def _create_attack_pattern(attack):
        query = (''.join((
            f"MERGE (a:Attack_pattern {{id: '{attack['external_references'][0]['external_id']}'}}) "
            f'SET a.name = "{attack["name"]}" '
            f'SET a.description = $desc ',
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
            App._find_CVE(attack['external_references'], "a"),
            App._find_CAPEC(attack['external_references'], "a"),
            "RETURN *"))
        )
        return query

    @staticmethod
    def _create_attack_intrusion(intrusion):
        query = (''.join((
            f'MERGE (i:Intrusion_set {{id: "{intrusion["external_references"][0]["external_id"]}"}}) '
            f'SET i.name = "{intrusion["name"]}" ',
            f'SET i.aliases = "{intrusion["aliases"]}" ' if intrusion.get('aliases') else "",
            f'SET i.description = $desc ' if intrusion.get('description') else "",
            App._find_CVE(intrusion["external_references"], "i"),
            "RETURN *"))
        )
        return query

    @staticmethod
    def _create_attack_tactic(tactic):
        query = (''.join((
            f'MERGE (t:Tactic {{id: "{tactic["external_references"][0]["external_id"]}"}}) '
            f'SET t.name = "{tactic["name"]}", t.description = "{tactic["description"]}" '
            "RETURN *"))
        )
        return query

    @staticmethod
    def _create_attack_malware(malware):
        query = (''.join((
            f'MERGE (m:Malware {{id: "{malware["external_references"][0]["external_id"]}"}}) '
            f'SET m.name = "{malware["name"]}" ',
            f'SET m.description = $desc ' if malware.get('description') else "",
            f'SET m.aliases = "{malware["x_mitre_aliases"]}" '
            f"WITH m UNWIND {malware['x_mitre_platforms']} as platform "
            "MERGE (p:Platform {name: platform}) "
            "MERGE (m)-[:ON_PLATFORM]->(p) " if malware.get('x_mitre_platforms') else "",
            App._find_CVE(malware["external_references"], "m"),
            "RETURN *"))
        )
        return query

    @staticmethod
    def _create_attack_relationship(relationship, json_objects_dict):
        source = relationship.get("source_ref")
        source_type = App._get_type(source)
        target = relationship.get("target_ref")
        target_type = App._get_type(target)
        query = (''.join((
            f'MERGE (a:{source_type} {{id: "{json_objects_dict.get(source)}"}}) '
            f'MERGE (b:{target_type} {{id: "{json_objects_dict.get(target)}"}}) '
            f'MERGE (a)-[:{relationship.get("relationship_type").replace("-", "_").upper()}]->(b) '
            f'RETURN *'
            ))
        )
        return query

    @staticmethod
    def _get_type(id_string):
        return id_string.partition("--")[0].replace('-', '_').capitalize()

    @staticmethod
    def _find_CAPEC(external_refs, variable_name):
        capec_list = []
        for ref in external_refs:
            if ref.get("source_name") == "capec":
                capec_list.append(ref.get("external_id"))
            if ref.get("description"):
                break
        if capec_list:
            return f"FOREACH (item in {capec_list} | " \
                    f"MERGE (c:CAPEC {{id: item}}) " \
                    f"MERGE ({variable_name})-[:REFERENCES]->(c)) "
        return ""

    @staticmethod
    def _find_CVE(external_refs, variable_name):
        cve_list = []
        for ref in external_refs:
            if not ref.get('description'):
                continue
            re_match_object = re.search('\\bCVE-\\d{4}-\\d{4,}\\b', ref['description'])
            if re_match_object:
                cve_list.append(re_match_object.group())
        if cve_list:
            return f"FOREACH (item in {cve_list} | " \
                    f"MERGE (c:CVE {{id: item}}) " \
                    f"MERGE ({variable_name})-[:USES_CVE]->(c)) "
        return ""

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
