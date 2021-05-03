"""
resolve.py: a recursive resolver built using dnspython
"""
import logging
import argparse
# from datetime import datetime
import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import sys
from dns.exception import DNSException, Timeout

class Resolver:
    def __init__(self, ip='178.20.231.180'):


        self.ROOT_SERVER = ip
        self.FORMATS = (("CNAME", "{alias} is an alias for {name}"),
                        ("A", "{name} has address {address}"),
                        ("AAAA", "{name} has IPv6 address {address}"),
                        ("MX", "{name} mail is handled by {preference} {exchange}"))

        self.dns_cache = {'response_cache': {}}
        self.timeout = False
        self.root_response = False

    def collect_results(self, name: str, dns_cache: dict) -> dict:
        self.timeout = False
        self.root_response = False
        """
        This function parses final answers into the proper data structure that
        print_results requires. The main work is done within the `lookup` function.
        """
        full_response = {}
        target_name = dns.name.from_text(name)
        target_name_root = dns.name.from_text("root-servers.net")
        # lookup CNAME

        response = self.lookup(
            target_name, dns.rdatatype.CNAME, self.dns_cache)

        cnames = []
        for answers in response.answer:
            for answer in answers:
                cnames.append({"name": answer, "alias": name})
        # lookup A
        response = self.lookup(target_name, dns.rdatatype.A, self.dns_cache)

        arecords = []
        for answers in response.answer:
            a_name = answers.name
            for answer in answers:
                if answer.rdtype == 1:  # A record
                    arecords.append({"name": a_name, "address": str(answer)})
        # lookup AAAA
        response = self.lookup(target_name, dns.rdatatype.AAAA, self.dns_cache)

        aaaarecords = []
        for answers in response.answer:
            aaaa_name = answers.name
            for answer in answers:
                if answer.rdtype == 28:  # AAAA record
                    aaaarecords.append(
                        {"name": aaaa_name, "address": str(answer)})
        # lookup MX
        response = self.lookup(target_name, dns.rdatatype.MX, self.dns_cache)

        mxrecords = []
        for answers in response.answer:
            mx_name = answers.name
            for answer in answers:
                if answer.rdtype == 15:  # MX record
                    mxrecords.append({"name": mx_name,
                                      "preference": answer.preference,
                                      "exchange": str(answer.exchange)})

        # lookup NS - root
        response = self.lookup(target_name, dns.rdatatype.NS, self.dns_cache)

        nsrecords = []
        for answers in response.answer:
            ns_name = answers.name
            for answer in answers:
                if answer.rdtype == 2:  # NS record
                    nsrecords.append(
                        {"name": ns_name, "address": str(answer)})

        full_response["CNAME"] = cnames
        full_response["A"] = arecords
        full_response["AAAA"] = aaaarecords
        full_response["MX"] = mxrecords
        full_response["NS"] = nsrecords

        self.dns_cache.get('response_cache')[name] = full_response

        return full_response

    def lookup_recurse(self, target_name: dns.name.Name,
                       qtype: dns.rdata.Rdata,
                       ip_,
                       resolved,
                       dns_cache: dict) -> dns.message.Message:
        """
        This function uses a recursive resolver to find the relevant answer to the
        query.

        TODO: replace this implementation with one which asks the root servers
        and recurses to find the proper answer.
        """
        #global count
        #count += 1
        outbound_query = dns.message.make_query(target_name, qtype)
        try:
            response = dns.query.udp_with_fallback(outbound_query, ip_, 1, port=53)
            response = response[0]
            if response.answer:
                # logging.debug("\n---------Got Answer-------\n")
                resolved = True
                return response, resolved

            elif response.additional:
                if response.authority:
                    self.update_cache(response, self.dns_cache)
                response, resolved = self.lookup_additional(response, target_name,
                                                            qtype, resolved, self.dns_cache)

            elif response.authority and not resolved:
                response, resolved = self.lookup_authority(response, target_name,
                                                           qtype, resolved, self.dns_cache)
            return response, resolved

        except Timeout:
            self.timeout = True
            return dns.message.Message(), False
        except DNSException:
            return dns.message.Message(), False

        except ConnectionRefusedError:
            try:
                response = dns.query.udp_with_fallback(outbound_query, ip_, 1, port=53, source_port=0)
                response = response[0]
                if response.answer:
                    # logging.debug("\n---------Got Answer-------\n")
                    resolved = True
                    return response, resolved

                elif response.additional:
                    if response.authority:
                        self.update_cache(response, self.dns_cache)
                    response, resolved = self.lookup_additional(response, target_name,
                                                                qtype, resolved, self.dns_cache)

                elif response.authority and not resolved:
                    response, resolved = self.lookup_authority(response, target_name,
                                                               qtype, resolved, self.dns_cache)
                return response, resolved

            except Timeout:
                self.timeout = True
                return dns.message.Message(), False
            except DNSException:
                return dns.message.Message(), False
            except Exception as e:
                #print(e, file=sys.stderr)
                return dns.message.Message(), False

        except Exception as e:
            #print(e, file=sys.stderr)
            return dns.message.Message(), False

    def lookup(self, target_name: dns.name.Name,
               qtype: dns.rdata.Rdata,
               dns_cache: dict) -> dns.message.Message:
        """
        This function uses a recursive resolver to find the relevant answer to the
        query.

        TODO: replace this implementation with one which asks the root servers
        and recurses to find the proper answer.
        """

        i = 0
        resolved = False

        ip_ = self.ROOT_SERVER

        try:
            response, resolved = self.lookup_recurse(
                target_name, qtype, ip_, resolved, self.dns_cache)

            if response.answer:
                answer_type = response.answer[0].rdtype
                # logging.debug("--------If CNAME found in answer--------\n")
                if qtype != dns.rdatatype.CNAME and answer_type == dns.rdatatype.CNAME:
                    target_name = dns.name.from_text(
                        str(response.answer[0][0]))
                    resolved = False
                    logging.debug(
                        "--------- look up cname ----------- %s \n %s", target_name, response.answer[0])
                    #print(f'ip:{ip_}, qtype:{qtype}')
                    response = self.lookup(
                        target_name, qtype, self.dns_cache)
                return response

            elif response.authority and response.authority[0].rdtype == dns.rdatatype.SOA:
                # logging.debug("---------Got SOA authority-------")
                pass
            else:
                i += 1

        except Timeout:
            self.timeout = True
            i += 1
        except DNSException:
            i += 1
        except Exception as e:
            #print(e, file=sys.stderr)
            pass
        return response

    def update_cache(self, response: dns.message.Message, dns_cache):
        """
        Update cache with intermediate results
        """
        domain_name = response.authority[0].to_text().split(" ")[0]

        arecords = []
        rrsets = response.additional
        for rrset in rrsets:
            for rr_ in rrset:
                if rr_.rdtype == dns.rdatatype.A:
                    arecords.append(str(rr_))
                    self.dns_cache[domain_name] = str(rr_)

    def lookup_additional(self, response,
                          target_name: dns.name.Name,
                          qtype: dns.rdata.Rdata,
                          resolved,
                          dns_cache: dict):
        """
        Recursively lookup additional
        """
        rrsets = response.additional
        str_rrsets = [str(x) for x in rrsets]
        for i in str_rrsets:
            if 'root-servers.net' in i:
                self.root_response = True
                break
        for rrset in rrsets:
            for rr_ in rrset:
                if rr_.rdtype == dns.rdatatype.A:
                    response, resolved = self.lookup_recurse(target_name, qtype,
                                                             str(rr_), resolved, self.dns_cache)
                if resolved:
                    break
            if resolved:
                break
        return response, resolved

    def lookup_authority(self, response,
                         target_name: dns.name.Name,
                         qtype: dns.rdata.Rdata,
                         resolved,
                         dns_cache: dict):
        """
        Recursively lookup authority
        """
        rrsets = response.authority
        ns_ip = ""
        for rrset in rrsets:
            for rr_ in rrset:
                if rr_.rdtype == dns.rdatatype.NS:
                    ns_ip = self.dns_cache.get(str(rr_))
                    if not ns_ip:
                        #print(f'name:{str(rr_)}, qtype:{qtype}')
                        ns_arecords = self.lookup(
                            str(rr_), dns.rdatatype.A, self.dns_cache)
                        ns_ip = str(ns_arecords.answer[0][0])
                        self.dns_cache[str(rr_)] = ns_ip

                    response, resolved = self.lookup_recurse(target_name, qtype,
                                                             ns_ip, resolved, self.dns_cache)
                elif rr_.rdtype == dns.rdatatype.SOA:
                    resolved = True
                    break
            if resolved:
                break

        return response, resolved

    def print_results(self, results: dict) -> None:
        """
        take the results of a `lookup` and print them to the screen like the host
        program would.
        """
        # print("print_results")
        final_result = []
        for rtype, fmt_str in self.FORMATS:
            for result in results.get(rtype, []):
                # print(fmt_str.format(**result))
                final_result.append(fmt_str.format(**result))
        return final_result
