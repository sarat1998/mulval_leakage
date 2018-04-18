import sys
import networkx as nx
import math
from collections import Counter
import re

def initialize_scores(G):
    fairness = {}
    goodness = {}
    
    nodes = G.nodes()
    for node in nodes:
        fairness[node] = 1
        try:
            goodness[node] = G.in_degree(node, weight='weight') * 1.0/G.in_degree(node)
        except:
            goodness[node] = 0
    return fairness, goodness


def compute_fairness_goodness(G):
    fairness, goodness = initialize_scores(G)
    nodes = G.nodes()
    iter = 0
    while iter < 100:
        df = 0
        dg = 0
        for node in nodes:
            inedges = G.in_edges(node, data='weight')
            g = 0
            for edge in inedges:
                g += fairness[edge[0]] * edge[2]

            try:
                dg += abs(g/len(inedges) - goodness[node])
                goodness[node] = g/len(inedges)
            except:
                pass

        for node in nodes:
            outedges = G.out_edges(node, data='weight')
            f = 0
            for edge in outedges:
                f += 1.0 - abs(edge[2] - goodness[edge[1]])/2.0
            try:
                df += abs(f/len(outedges) - fairness[node])
                fairness[node] = f/len(outedges)
            except:
                pass
        
        if df < math.pow(10, -6) and dg < math.pow(10, -6):
            break
        iter += 1
    return fairness, goodness


def create_graph_and_counts(path):
    G = nx.DiGraph()
    counts = Counter()
    try:
        f = open(path, "r")
        for l in f:
            ls = l.strip().split(",")
            G.add_edge(ls[0], ls[1], weight=float(ls[2]) / 10)
            counts[ls[0]] += 1
            counts[ls[1]] += 1
    except Exception as e:
        print e.message
        sys.exit(1)
    finally:
        f.close()
    return G, counts


def compute_trusts(fairness, goodness, counts, principals):
    trusts = {}
    nodes = [node for node, _ in counts.most_common(len(principals))]
    node_principals = list(zip(nodes, principals))
    for node, principal in node_principals:
        for otherNode, otherPrincipal in node_principals:
            if node != otherNode:
                trusts[(principal, otherPrincipal)] =\
                    fairness[node] * goodness[otherNode]
    return trusts


def leakage_to_ac(leakage):
    acs = ['h', 'm', 'l']
    return acs[int(3 * leakage)]


def leakage_in_prolog(fairness, goodness, counts, input_path):
    try:
        f = open(input_path, 'a+')
        principals = re.findall(r'(\w*victim\w*)', f.read())
        trusts = compute_trusts(fairness, goodness, counts, principals)
        prolog = '\n'.join(['leakage({}, {}, {}).'.format(principal, other,
                                                          leakage_to_ac(leakage))
                            for (principal, other), leakage in trusts.items()])
        f.write(prolog)
    except Exception as e:
        print e.message
        sys.exit(1)
    finally:
        f.close()


if __name__ == '__main__':
    if len(sys.argv) == 2:
        G, counts = create_graph_and_counts("network.csv")
        fairness, goodness = compute_fairness_goodness(G)
        leakage_in_prolog(fairness, goodness, counts, sys.argv[1])
    else:
        print 'Usage: python2 add_leakage.py <prolog_input_file>'
