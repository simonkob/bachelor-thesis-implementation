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

    @staticmethod
    def _create_pulse(tx, pulse):
        query = (''.join((
            "MERGE (u:User { name: $author_name }) "
            "MERGE (p:Pulse { id: $pulse_id}) "
            "SET p.name = $pulse_name, p.description = $pulse_description, p.revision = $revision, "
            "p.public = $public, p.references = $references "
            "MERGE (u)-[:CREATED {created: $created, modified: $modified}]->(p) ",
            "MERGE (tlp:Tlp { type: $type}) "
            "MERGE (p)-[:HAS_TLP]->(tlp) ",
            "MERGE (adv:Adversary { name: $adversary}) "
            "MERGE (p)-[:HAS_ADVERSARY]->(adv) " if pulse['adversary'] else "",
            App._create_pulse_subquery("Tag", "HAS_TAG", pulse["tags"]),
            App._create_pulse_subquery("Malware_family", "IN_MALWARE_FAMILY", pulse["malware_families"]),
            App._create_pulse_subquery("Country", "TARGETS", pulse["targeted_countries"]),
            App._create_pulse_subquery("Industry", "CONCERNS", pulse["industries"]),
            App._create_pulse_subquery("Attack", "HAS_ATTACK", pulse["attack_ids"], "id"),
            "WITH p UNWIND $indicators as iItem "
            "CALL apoc.merge.node(['Indicator'], {id: iItem['id']}, {indicator: iItem['indicator'], "
            "content: iItem['content'], title: iItem['title'], description: iItem['description'], "
            "is_active: iItem['is_active'], expiration: iItem['expiration']}) "
            "YIELD node "
            "MERGE (p)-[:HAS_INDICATOR]->(node) "
            "MERGE (type:Indicator_type {name: iItem['type']}) "
            "MERGE (node)-[:IS_TYPE]->(type) "
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
               references=pulse['references'], type=pulse['tlp'], adversary=pulse['adversary'],
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
