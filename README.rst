.. image:: https://travis-ci.org/spesmilo/electrumx.svg?branch=master
    :target: https://travis-ci.org/spesmilo/electrumx
.. image:: https://coveralls.io/repos/github/spesmilo/electrumx/badge.svg
    :target: https://coveralls.io/github/spesmilo/electrumx

===============================================
ElectrumX - Marscoin Edition
===============================================

  :Licence: MIT
  :Language: Python (>= 3.7)
  :Original Author: Neil Booth
  :Marscoin Integration: Marscoin Development Team

Overview
ElectrumX is an essential reimplementation of the original Electrum server. It was developed to provide a more scalable and manageable server solution, connecting directly to a full node and efficiently indexing the blockchain to facilitate quick and reliable querying of transaction histories for arbitrary addresses.

This project originated as a fork of kyuupichan/electrumx following the original author's decision to cease support for Bitcoin, which remains integral to our implementation. The Marscoin Development Team has adapted this robust framework to support the Marscoin network, ensuring compatibility and enhanced functionality specific to Marscoin's requirements.

The current fork includes support for the Marscoin network.

Key Features
============
-  Full Node Integration: Directly connects with your full node, leveraging its capabilities to index and query blockchain data.
-  Efficient Address Querying: Allows for efficient querying of the history of any Marscoin address.
-  Network Support: Can be set up as a public server, joining the global network of Electrum servers through peer discovery, contributing significantly to the Marscoin ecosystem.
-  Current Adaptations: As of May 2020, a substantial portion of the Electrum server network, including servers dedicated to Marscoin, runs on ElectrumX.

Documentation
=============

For detailed information on setup, configuration, and management of your ElectrumX server, please refer to our comprehensive documentation available at Read the Docs:
 `readthedocs <https://electrumx-spesmilo.readthedocs.io/>`_.
