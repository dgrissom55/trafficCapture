# trafficCapture

<div id="top"></div>

<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
![Last Commit][last-commit-shield]
![Repo Size][repo-size-shield]




<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/dgrissom55/trafficCapture">
    <img src="images/logo.png" alt="Logo" width="80" height="80">
  </a>

<h3 align="center">trafficCapture</h3>

  <p align="center">
    Synchronize network traffic captures on multiple CPE devices and their associated OVOC servers.
    <br />
    <br />
    <a href="https://github.com/dgrissom55/trafficCapture/issues">Report Bug</a>
    ·
    <a href="https://github.com/dgrissom55/trafficCapture/issues">Request Feature</a>
  </p>
</div>



<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

![Product Name Screen Shot][product-screenshot]

The goal of this project is to try and isolate with network traffic captures any anomalies that may be preventing certain traffic types from traversing a WAN. With the scripts in this project, the task of automating the synchronization of network captures on numerous audiocodes MSBR CPE devices with their associated OVOC servers, and collecting the captures is handled.

The script `cpe_capture_app.py` is responsible for initiating the `debug capture` commands using REST API calls to the MSBR devices and synchronizing traffic captures on OVOC servers associated with the targeted CPE devices.

The script `ovoc_capture_app.py` receives commands from the CPE capture app and initiates the `tcpdump` that is filtered on the targeted CPE devices IP address.

 

<p align="right">(<a href="#top">back to top</a>)</p>



### Built With

* [Next.js](https://nextjs.org/)
* [React.js](https://reactjs.org/)
* [Vue.js](https://vuejs.org/)
* [Angular](https://angular.io/)
* [Svelte](https://svelte.dev/)
* [Laravel](https://laravel.com)
* [Bootstrap](https://getbootstrap.com)
* [JQuery](https://jquery.com)

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- GETTING STARTED -->
## Getting Started

This is an example of how you may give instructions on setting up your project locally.
To get a local copy up and running follow these simple example steps.

### Prerequisites

This is an example of how to list things you need to use the software and how to install them.
* npm
  ```sh
  npm install npm@latest -g
  ```

### Installation

1. Get a free API Key at [https://example.com](https://example.com)
2. Clone the repo
   ```sh
   git clone https://github.com/dgrissom55/trafficCapture.git
   ```
3. Install NPM packages
   ```sh
   npm install
   ```
4. Enter your API in `config.js`
   ```js
   const API_KEY = 'ENTER YOUR API';
   ```

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- USAGE EXAMPLES -->
## Usage

Use this space to show useful examples of how a project can be used. Additional screenshots, code examples and demos work well in this space. You may also link to more resources.

_For more examples, please refer to the [Documentation](https://example.com)_

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- ROADMAP -->
## Roadmap

- [ ] Feature 1
- [ ] Feature 2
- [ ] Feature 3
    - [ ] Nested Feature

See the [open issues](https://github.com/dgrissom55/trafficCapture/issues) for a full list of proposed features (and known issues).

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- CONTACT -->
## Contact

Doug Grissom - doug.grissom@audiocodes.com

Project Link: [https://github.com/dgrissom55/trafficCapture](https://github.com/dgrissom55/trafficCapture)

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

* []()
* []()
* []()

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/dgrissom55/trafficCapture?style=for-the-badge
[contributors-url]: https://github.com/dgrissom55/trafficCapture/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/dgrissom55/trafficCapture?style=for-the-badge
[forks-url]: https://github.com/dgrissom55/trafficCapture/network/members
[stars-shield]: https://img.shields.io/github/stars/dgrissom55/trafficCapture?style=for-the-badge
[stars-url]: https://github.com/dgrissom55/trafficCapture/stargazers
[issues-shield]: https://img.shields.io/github/issues/dgrissom55/trafficCapture?style=for-the-badge
[issues-url]: https://github.com/dgrissom55/trafficCapture/issues
[license-shield]: https://img.shields.io/github/license/dgrissom55/trafficCapture?style=for-the-badge
[license-url]: https://github.com/dgrissom55/trafficCapture/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/linkedin_username
[product-screenshot]: images/capturing_flow_v1.0.0.png
[last-commit-shield]: https://img.shields.io/github/last-commit/dgrissom55/trafficCapture?style=for-the-badge
[repo-size-shield]: https://img.shields.io/github/repo-size/dgrissom55/trafficCapture?style=for-the-badge
