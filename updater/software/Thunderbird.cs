/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023  Dirk Stolle

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Manages updates for Thunderbird.
    /// </summary>
    public class Thunderbird : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Thunderbird class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Thunderbird).FullName);

        
        /// <summary>
        /// publisher of the signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 20, 0, 0, 0, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Thunderbird(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.2.2/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "8a5dfa90ff4af341e9222657922858d550ac1a500a15d1e651f36e99e7e18853faaaef1b9c888036771eee7009b7abdb8d3464c2d657e81c0992c643b2df54da" },
                { "ar", "9def30a6bbaa8940d0a8e4d319074f751d3d4823b71f879ca3d5e7ae1c72005d7d070a2278a1f5506b58971c350369e727ddc3edda53db7fbae6dbec2011f97f" },
                { "ast", "a8495a3b7170f8757dc23dc58d0fd9f3b28d265d9ecfb57e1fa799539bbaa77b34c4734866fabdf82367c7b655eb3c799c7e28358e285d2c6535954f7dcb4e7f" },
                { "be", "24d577353cc51ba99161126b7fcd11bb8e2e08fbeb7ea66d63c88d1d607ff2cf0362dece468b851c957fadf173804b31b9e6dc0e73ee82612b3876e7a33a8806" },
                { "bg", "8a264abc0318c45e65f2eeb5a1df088b078f077520ace1db26e5bcfcb4b631f70c994d850ac8e80d40808c35ba7ddf10c17e93aa24b0535425a8f1fd9924ef98" },
                { "br", "01046948c154d387ca8648ae3e14eaf6b56f5ec093117d55a018015edb5b79fa4016cd1458de662c116358b817725e4b94a0e5ab012a170c5ba2369da5545b7d" },
                { "ca", "f55bcc638c721bf5ffa21207299e83c2cdc58154bfcd4b8aa8da1f6f01ca7a2edd169b2345b326d1903b4420a6c2a0e908e3d4969b18271ba485aea987f4aa57" },
                { "cak", "046e2ca94c9b076a4098fedbba0e38b33c11e2ed83eb5c2cb054683953bd89d5a006ec083f0ca9e330be605d351a3a88e383b3d7e595981364a8eb82f5a1b210" },
                { "cs", "517c8b3e97bdbd7c62b649f4d380c6a01462a6840a8c8ae24cb66003b4310776b57a3968b3af2a6faaef1198df7b8d58bb7326120b4923029770d2cdf357e4db" },
                { "cy", "4aeeb3821980f81220850020e956d730a15f8a7c067f3db473eed3bfc9de4cb18575fd6c25fa000088c4d97bdf34b3e0d0ebc720ccf7d98e0189d7e76c9e6bfe" },
                { "da", "7834f21c69290c28a161bd7ddad60249d4417d2871fe6df17a3302cdee44c2dbba401e99655881be5da5448e48bc68b9f05d2270bca68af5ae11c12446be1506" },
                { "de", "7055232f00d7d703e9b7da1e34d83970dc641432cc0570d6a3a590203e958e873add51fcac78fa8046e7d89ac145b989b5c45a1c47dd6960f84a7fb3b5feb55c" },
                { "dsb", "bc71d36f06b32a7d55df6ae1a4d52cb08317d0465d662af6a45ab280e13c6e461ddd43e38cdb59f3dd6cfb2386ec15d7974f330e1451f4df7b95375b7c3e1ab8" },
                { "el", "d99f69ee2e78d4101bcdc467bf64a35b62094f0ac87df02744e0de2837dce984cba5a5599020c351f8872c2748729b9cb12970bbb42e543875ea0d318d9c75c7" },
                { "en-CA", "32396f2282beac6aab46b476820b879c2c7c3b792e5eb3d51300480bdcdffc2e9555d5c04cf17cbfb1f716623b30796e09edef17ff6dc91a5da466a4e75e7241" },
                { "en-GB", "22401b39f179277cfb7f74dd5508d01f05065a228ac44c8916932b03bf2e06ce64ca3231e27545b70a11799eb880be147dad83bc671073f133d2476940268111" },
                { "en-US", "0233a9832b13d14f62e8649731b207ba297f537c8a4183ba88ac38873637f6f694e5580af9be982ec560edec9798dbe5c083eeb2fde0b0bd0e4805f14f3685a2" },
                { "es-AR", "5e3d8db24c353ccb1bd806c7e4f415cddbaa22658896dfcf41c85156c5391c2f3ccd36064d0ffe858b0f228d7a5d8fd13d1fca5d92fc1d941d1c73178e500f4e" },
                { "es-ES", "b656721957efc65785dcb5d32cc1fc9e570ad095734293628636bbc74a671026b7c980ce54952cd535f3ce31a52a87e9ce1fc193e64963e96327d1863c2e0a73" },
                { "es-MX", "1f0e5e208e65178ddf46bf29542248f94154d7102d40ef1761692cc678b2ce3b2f7fdc9cb775c8370470d0f8b292211bc637d7b14b4678dfd7030dfe4218f9d0" },
                { "et", "4463fb71652106388fab71fdcb3d24c9ba2c6d52d8564bc9848f0603a59bbe68e63db8981b670a6385744af59210f3676d9344fd6b0e831f29eb5e7f7447251f" },
                { "eu", "4c7ac3d587878918d31243d78b36ee2ea4e295e4d310be12bf1c5d267e37c7328e4a7f0077a5018141a4fe51f5ee8b4e3dc8f48591745e4d0089d3c9b57421b2" },
                { "fi", "28df86e57b6b68769790704847ab2bb1fe12fa0e957c82288e255c5a270f22479f223ffb707a3ba756516dfede2e517ab188939b1211fd4701ed181f0c9c42b4" },
                { "fr", "47d45659c9531bd3e70a749c859a16c59e02202a7d7d1b30921248cf881726da7462b3e2e7e4cf2f1c8941a56d5cbb922218ff8ad714c5820871c19d03597199" },
                { "fy-NL", "a96984d296ba94eb54ac537f48517976403de24982bc79420349cfe6c1b69bccdc8b5e429dbd8a5a10d1c2a4edf06bcea5bde420b926dfad04a58eae9cbd1fea" },
                { "ga-IE", "61330b12fb65058c22dc3073dc0337c993a193450ec1a8e7b17790297300910d6a76fc1cc054f94d45c6664d66e946f505fd6de0795b34371b4f5be035373fea" },
                { "gd", "1f1a43c4b39ee89797f53e7e6aea538c9a18be9c70020fe1a1c32d8d663794890f71faff0e422ec27264f133e7b2f8ce075846bde348fa89ec1cabd837791b1b" },
                { "gl", "04cfbec071984853798fb52679a7d6c021d46629947033805debc1c3dea604d3c57c6fcaa0c78242da4a0752ea53f6023150d57e99270c70d847740c841b616b" },
                { "he", "ef0b5db24907e3308c2c230cbed173818e0136c1327e4d941bc24a5f2825e02a463f5e099f908f0aa5d2e305b64def370598741e2d2cc8c01c4b54ab38b8fef7" },
                { "hr", "ee8e15ee1224757107cf5bc7ed811837aa44d29be2afa7bc8c709e615619691ef386d4eafb986e1b4af035bd6d76db01cd678afd57a2a88ae2baf1712a763d42" },
                { "hsb", "efb1b0c0d19ee3f38700a30c68770957841175cfece203d0371de17762a9408be7c5a9e9efeeb15680e09de5c44ce7f5d20fd430f72e73168ac1372b4def2a2c" },
                { "hu", "bbc616e5142386624198855bc32de32c453cf20e6064a7f6a62f0111fd1e9eee441ec44e560694a22699db717f82e1e5f8b961e5b0e2170cdcfdb92afbd639fc" },
                { "hy-AM", "2e68ddd416683437bdd8c444b20859b29b6704d70820b46d3711dd9527e4829707f0d5f5415257c708c5ed8d8b6b2464a23f7fb79e42e6684da6c7e48120800e" },
                { "id", "99bf01921870d80da0992ae98e8b61db1f9315bdffb19cdafce87e7f4779cde2359d00f94a34f752102c76ede07218a2fd2f941ea8969fbae1c010a820ee15af" },
                { "is", "c93514b0a9eeecf2135dded7b0f805ecc7720fe810184b5647d4b4e22c191062ea87fcb8b5c3027ac8feb90b9347af30346328dfe11b4d248d1780739a524997" },
                { "it", "115be8a9fa71074069ad20ea614beab0d50b33b5b3a2012bc611e8c7431466a7eac1ae824e40591de8475a7efadf4ffb43d8362950722222d4112b8f5a6320d1" },
                { "ja", "b214076dd7456ec6239c87c11eb81666c186ff0d2b1a57c4ed787d86ba7c8b86f4ea98834fa2cfa20c8975aa4e88ad135e701ab4e3ae02511bea0fd932ee7ad9" },
                { "ka", "05e2e501aa97cc9f399a1bac0fb4581ac973a191f84cfb2bda99f5295558f0af55617010acb896beec91b1271baf40f68e2f04ffe1359f8098933445ab948690" },
                { "kab", "491ebc0df20ad45b44ef231edf16a6f3dadff4ade3a7fe3ec0b8d51153cc30399369d11af1fdd2f68034330fa3fb14b0ea04f80d253b79d3b57c75ae71f1fc66" },
                { "kk", "0d2b609d080192ed48a7a8e23a89ba0a00704c610eab0b68789f6272901856fbd70ccf9d44a67e2d14f5f2423ed8879f9de48bd41ce0cce90fbebe2352b266a4" },
                { "ko", "851dcabef5fefb5afaeeb27dd98531bb17ba11413e2ff3cd3e9a539d8a533038cf745e6313d76b5bad844454a9c0f6dba26f2646eb049c2e1333d0edf6bf4644" },
                { "lt", "c7d4fbd42e79a411cd788158e7fa85573d9c4246c606c73daa902090050b5496c6438f94b42cd5542c8acb5d1d7a99ba644e8221a896e055d85fb09fe96bcc5e" },
                { "lv", "fae28b3179ed965a6ace3cac90f6b058c4faa5e62170f5447a339f9506c94db03a4c9130e037543856297a562e2797a1e78c95d9911e5bee7cb8088ea61bd052" },
                { "ms", "a77db85e75867c1aca21638450dab89b55a34c82f68833a9cca3a89ae0162e9c7baa6397e63a3e5fc7191e766fe0c0acce270c3be1a0db41944704301e3e27d0" },
                { "nb-NO", "5c2f3ea3f328d61ba88cd89d0d5c12459de968ddf6dc5c652767287e87ee2d9852501d791fdc42bc590b250e54c779af904ee612c1f7d36dd3ae6bb06c5f7b88" },
                { "nl", "1fa547ee4e45ad4db0c7f6ca056ddab6384003bd46cbbe539403b156a2e416903324cb16644e4a29cf26b7f13d02c6c04fb492769fadfd0fd0657c60d977d49e" },
                { "nn-NO", "15cc8f0b4cfb9bccaae4222828d9d8dfa352e3e19d06d8d35a524db8f9bb7d495bc0e003523bd49db82adb3517ed3ca02023ef15f1c475450cf58a1295eba820" },
                { "pa-IN", "eb4bd4d556773b63c8a7596f9ff74e46414df70879d8d1cb14923fa3f98fec4e2072ef6e7e41a6460a74a3590025a45a816b132dbcd26d2e392178e29218a6c3" },
                { "pl", "dc790e12a9d5f8f4572d40ea0d03995f31b8af509dc4d2a8e559b4e5615659656d8cc39cc55a84bcee6df4d0f8d8e4922585373b7a47891f4de9a09abdbb7769" },
                { "pt-BR", "7e7b8d9ff3b456858711a8115435a4cad35afa8cee77c7299dc72cb2a7099bafa255a88bd81d8a865ea7bd467485d484ea6d531c88ffbc132698133b30c148c1" },
                { "pt-PT", "87a546d7207413cac07e617ad047ea4019653bf05af57d0c00d0a5bfe253309f1c5121ebdf92f0a4a5b87583708650ffac756c08dcd5719b171a0c5b721f858f" },
                { "rm", "ca4a76a5581e410bfef23d6d396ac614bf305148d1f35ce728f0c38429618b7910466b1b82b5d0da270f755a659259e23fa2fdf9fa982d0d5ac9a0760031e527" },
                { "ro", "a95b912ed55ba8c92948f946f30ad726b44eb9801e34283172bff7356357b381ab6c0026fd7216fa8ae213d84a500fd9267fda4a2afdb4362476303ec40cf498" },
                { "ru", "ecdfc55f8678460a39879a6d5e51af38363c0edabab6ab3c6ab70261cdf316a06d23611358f4509118120bef2a7dc8ae32dbda3838466d1ebb357a51f88400af" },
                { "sk", "9d968b57de119fd6c56912b89e1af1bb55f523caf4863e088e0593005e6d277012821e79265fb61331b1a27311d32c7cef4084275c449aff99f563b7bf7fa3e9" },
                { "sl", "f38ce0488f73f2abfe3c99372bef6eb35b2224df6a3c530d393924decb4a59be8b657b96f08235dd839f230b2e0e6c576bdb1d3aa4bec7c9ebb5ddfc4a626293" },
                { "sq", "d9263a2f3d40522b0ba7f7f9d19a915eb0bd2bca3c5e7441d72bb807636f775368b2c083f977f83f9797297cf05906ce988163d8b8df62d2e44eb2a1055fd489" },
                { "sr", "e13cd218628a5355908c271717e21e78b91c3e0e815e6bd903925ad6e29def56d0a5111f592119dc3b04fb728081517d4d55e9e418e50e0ef43f69d64080a57d" },
                { "sv-SE", "8bccd07e9101ed2e01f4df05b358dc9ec9264acdbbbdf266c8b7e3aa8d955eef688703e06f0abdf531e49482dfc617ae725589cb52d710df4348fe35aecc8e60" },
                { "th", "49c14ac02278620e53255975def23398915226a6163c20230a73eb84ec34f1a6d9007614595ca4263956440a1ccea730f96dac1250e71610911d5cd69c2fc626" },
                { "tr", "47da4eca3219b8bc2f5dc8824c615f23c2efc6cf4d2590bf9b91b1d9b86b86d819730873d3867357a7c4ebdec2d2ab1812b1911f60d01fa2c3b926193d4c66b8" },
                { "uk", "2ed17d09c57d4fd6e31e105f925f2f8edd0a6df73e37e9b8c85ee06d776d9544c4d5af90d58be2df6799f2f808aa6575d5e6420a1718e4de6517896ba5ff44c6" },
                { "uz", "c2bc1a91ba43b632c18659c27c427d0b8d342577e5ad2cbc08fff2ad961d7f0f33c9eef9f79c3df82b09bfd2a787d89edc747b640e03d4195644357b5cca15c4" },
                { "vi", "c79799e9276e9c5de283b83ee9ab516b0d930c74cacbc41134d78fd670043185e512950c9fb1b4ce711e587dd567878ecb87b13e4feabe09665daa43728cf4c3" },
                { "zh-CN", "5f6b812c34715cc438ffe67f05e4ef49e968eb8912ce51b2a2613f953f2796b9d429dfced30b3af857ab9cd44c59fbd7c298ebd7e7eeb1c353a4c2dff41beee4" },
                { "zh-TW", "d77c15854869a7f3291e3203069a983d6aaac7fc5da9523e2bdc7e6b6f0a24bd7addf6d457e94e2e967d2ee296da431da8b6b7afd1f16dac96196b5262690c2b" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.2.2/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "ef4333cc283284b8bcb5a50ffdd847534338f16afd1226bac7d6c96282962e5b586d5301b2555d2ad14610b6cece492ef3d8540e74f07210b18a4bba042d5776" },
                { "ar", "53f5090ac02d2a55208c469daa18a96cd6fdc204f0c80fad50ec44ed3453920300abf60aa90321ae0564488cf48fd868f0d19ff91ecc0dd5ea1ae5ab5e88f2fb" },
                { "ast", "26adc9fbe9a81485710b841a3859a34308c55a983a4f591a3e4bb3e4b473a08de3ef4f2ddf07728fc98801bd3c53c53fdf3458dc25be57a517040fcce7900e50" },
                { "be", "fb0a2bead39d1dfb14fc73ddfb71f298955814ef8eb128900aa7adaf6923a5f4c5c26b4ebef6c074b9dba1391fb65e93c8144b3c07ac73fbd9583b01909a9797" },
                { "bg", "0f633251e327dca3a208ac9a8bf42316c7445feddc04ae172d59cf434ae0cdc17470a3635c00ddf207d4bbfa340139ad1b506f845ae81afd00364ea06e520597" },
                { "br", "1cbc53ce7ac20e85998c53c912ece335e14d73d09364fa25a4840db1215f0593bdea96f7977996328b205d96a049b9f8d23af2a0c62d16202daf970143a7140b" },
                { "ca", "709269ac39dde5990081fe3148c65efbb7951706c1935db6977eb232bc2ba5574cbfb1447d0675c847d49f694d68988b9aaba43bbc16354569db173374e62bf9" },
                { "cak", "2c42b49bc660f6f0241b22ba5d8ef23f594c6df74b63d274103b19737d6bf9fd3361c6f9d56bbab500adbed7eae5fd4fe7ef17deac9ad25e636ef0f0ade77496" },
                { "cs", "d0f36759de59aad467325c740186ccf57725c2d575fa3064dd35398b649fd1abb63af8069dcddbf9ae452b96ccf0499d6b3fba470f4ef097c83cb3e3efc1f80d" },
                { "cy", "d584f15fa75e37d0715c486cc9a2eddff6886738ee81c5e8a17e47e5284596309057fb6a8c5a62d79716f753dbe78e04a0794b1a463a939c9c63aa5d6bd9df85" },
                { "da", "c0ebbac6c40600c614f0e230bed01d2242ad0104e513f0f62e83f5d2dd7a430b474450b59014f904d5484475f02d4925eef0cc8b12a2a15236480add8d7a961d" },
                { "de", "2d3261e97913f320ad6e4700582a84108656833a36b79480f1d8e386218dbfa834b2f0e6a12a47cac6885fc38a3dbddf33b6eddf8b10d7b56642663d2bb58325" },
                { "dsb", "04933882467a50d681a74291415b33b9bd8c1bd40890600e76a830a72e4fb13bbb76001805fd06cfe5cb702d5fd2449159d45629358831a454b79290d55a16b6" },
                { "el", "d9ed77f28aac803c06c19082c7de14ddebf6d586a426482920fac3f2b795a8682b6bf91910204d3bd5bc4578c663713dc728a754b3a9e156fdd2c4081c126db5" },
                { "en-CA", "6e291c8d62dfe4330c0c0bd097eec38c4aac03afb2d40c920c5c90d6c87c1491154e52bfa4427419207698ab6127b97a6cb9bbbfdcfcb0d4b58093cce483c867" },
                { "en-GB", "b81a39679dfbd4243787e23a2e93392343b44e85932d9168f0a738bf0467d6d10ec4974e9fecf65bf75ab076758e237d14ec399824297eb8b4c493b2f9e5d71a" },
                { "en-US", "a7bbad9aff5c7d41694716e624b8c2fb91dc20de1ea577bf62f9726ea217fb030a9f8e9a4a44e0a84923afa14087420c601f14e17d30d5ed21e8275f45a0a83a" },
                { "es-AR", "2e0e3774aa55691cd28fa04ccc5eadfbea8cb2d9b0239f0bbed35bd53786e5016908209d141e5c49a9f1d668e3a01c227a5b686d05e8f4f9fe21de09c4d1ea45" },
                { "es-ES", "13735d022796612f35bf3ad517d2296654fab576befed2dac96aecb79b8a22c95f09e68da66a37e3f2d231c2e2cf67a70db1089e60fd69fe14198d75ca7c250c" },
                { "es-MX", "b891f369b3ccadd7581525612015a41e80805734312f88b9348f2d7b66fb8cd93d364af6282da8a61cb7bc5869ed9369b6f177427e92b4f67daea70b060cb5be" },
                { "et", "7214c74a61bfd97f69aa4feb141dcaaa4b068dcadef106f96ccd430d18b5aad21f50ded606bf760b15c1f19eb7d6674bbd5a0f3c7e3aa8eab3ccfb6ccacdb57f" },
                { "eu", "350b09ea377a645d29f903b1d221a3f256b4406054073b29b657f82d2d355951117767cba013b9b27df41ac70bfb8553cde3a902fb870290bff1a86398d75362" },
                { "fi", "172c1caf3a6ca6c3237879a06b712d04d8f24e93d6602bce8c9c9e217cec973867af16b8063a496333d1bb91cbb690be291363bd1086df5b786a1d40f7c273b4" },
                { "fr", "4253028bb292cdfb94911c322c3bbe1be46ab6c761f59763ffc9ffe59ca6801badfba97cabb064de6949e030fe293268b4a4ff9e5c79653e1890dbd6edf9efd2" },
                { "fy-NL", "d811db2a607dc8327250312187355d25da41c7d7a9ffd1cbd2f9adb8d0fb945d8b2e2db56a48797dca43f4c4759a27fbb0e3f14905245b5dca17955eb94b3f2b" },
                { "ga-IE", "53e9982ccff3b7bbb1ec652776be4444cf5fb7c31475918e494cd9c7efd7af875c601dc4c1684786ae54a4d42e37a06166f274d8e4be186842eac979219bc4cf" },
                { "gd", "6f2178a68adab4a9c31b7404679668d20382af010a5e8b6bfc3c395884dad64a25453ca3b755f37caa9bc003735ab0f1d3a533d922a3beb7bd6aef5da41c1f4a" },
                { "gl", "405b68425d86a826e5462224b09bafc2b25b1251bbbde9f2bf8593e90d2d5f1a8bf5a3d7b10a2f7b032a6694aeaaa7fdae5a0c3096ac11dea539c85fe1ba40c8" },
                { "he", "1fc2cb3b59eb1d2d0622d3cd212f0cff5d9e6dad22358de4b69bbd1c61e29c236e88016148eda9b9bb4247888c714014f66ea4f64e4653cad32eaf77c125c1c3" },
                { "hr", "797eada4086965407f4eeff352e7b7d0c7bf2394cc7101dab339d1df5a4d159f7c92c8a9d88e95ca92f3f748461bf89296ca8c352d4496a4829b9ee0e646caf5" },
                { "hsb", "0dfffd19611e1260f5002f58575eef76fb1e359056bca8f11538a0b5da516574245b89e4d5200df6fa1c66873751a70ded59a0c36ebc3800957fb1a3e94705d6" },
                { "hu", "70745ad98431d94d87fd06f179d45c3ef51bd5db55d83b02dd7bbe5d8344815bafd3b173463e706dbda9722c9c88f0de89c54380a17b02f7aa3dec18f126b31c" },
                { "hy-AM", "553b78963526a5c4de667a3e58bfc80820e4f25ed9f5599f0834cbc808bc084f1a3e36568fe7149f57af84e37207a3f4d32992c0a71e690390ad04a291467d38" },
                { "id", "7179f11cb468415ca8f4388218e60ebb97cd209ad461cee32127f4f217d48c8ca0701bcfd09bc7341d9e4e12277b17153a591aa2213f0619c6035f6dbc949cdc" },
                { "is", "376d6389945ed93adb74a8ce6f7a6c2f443eadefd20371bf3bc11925cf6ff9364be068f21a62b71928503c0737510519a9f9d3ea822234cd5a4f17c4751ceb30" },
                { "it", "b0396ca95b804d0da248986c13db285191f33eb3c7b0d57f8f8a3a2d4d0c31cd00c440fd6cbbe88d1606577b4ac4e5145c9c9dc17f2adf9b3effb2f2739d2e9c" },
                { "ja", "65e35cb8713e152fab3bac1f48945f881f6e725872014787ff63d41ed1e7eb12bad092866f0321911be6e3cc55622a997de3e1e0cb00c644fe816971b52bea8b" },
                { "ka", "ff4673a8fdad705e1e61aa50af8b91059fa944c6d27dc6f5468c49f61ce89dbdc694d9f399ee1a6d8992e4f6f0f84a564bf0732904d7c447eb994ff5827da525" },
                { "kab", "7af6301fcbaf25135336cb4207a16cbbb7f12aa0e98078ba858be657882a936ae6df1a24f15b6aff2187e651338456e33745e4f2a1b00a2c78565df8fd4d6f41" },
                { "kk", "77eba64d74737f7dcfeb7d3a67e445a7338aaebd1f20d5b5647c14570396a8787146c129ab8cadfaa2bc4958bba8d2298055e24bba85a608dbfdd254c421c24d" },
                { "ko", "a1ce3497370d8bbe0836c00d4e5f8f98e573e7f3221136e631e4958319487bf21043aaa69708ca800d6cfe97a29595582aa59ff78cc29829be52fc02265f8932" },
                { "lt", "ea6a7a2a004027787bc159ca0b7c0a67d16992e9e6b83783606a75f44fa4acd8daa6f5e81e870686baf8ab231e7673b89112630957b1c354daa5db6dbba0f4d0" },
                { "lv", "70eb58baeda0c89ba303805115058d7056896b1c55a065ecd8ba0d932625bb251b7116b29dc0b28a39e4f72cb6cad22f827196d958fcc7f9202c620c10847555" },
                { "ms", "43c37a47d39834f588ff884d02ffa9e43b76f2b6a817cbed014924f20900b29ef84909955a218d665cb543d7e57e713745902ca94637cda3039c34eb81641963" },
                { "nb-NO", "2b4d5b787965ec8daaf2a80105a634e5191164a83467d3631e1db66711b7fd2fa8d2309d662ecb2bd219bd623fed7f93f6c82de684e496b606e0cb936db1ef56" },
                { "nl", "2d91c5d738c6d117c9cca8e43ea91740b8fbc4cbcfbd5563ad270911bbaa9e62f38c28059d0699347440f7f7d012f5de2d660a655c94dd7c7dc574deb8090b74" },
                { "nn-NO", "477cd060c178d61cac04184f7fc60433a4bb82295fd7aa2835904d17fe3b1a1ec85f473a3714ef0bbc2948c8206bbe29ce6e1532b092cb86ef01f2f6381717f6" },
                { "pa-IN", "299c3672d502d3f162cbcd1e33fd666de78eb457cc89282ee4d79d6455acbf6c1543d112044db7c45d860210b58cecfbeff97537956e2cc1f3c1ff4c7246d783" },
                { "pl", "53793e82c03dbbaf568e5adac09c587a66effe4f9810ad16b501aa9dc27c73033e3c04359af8b53faa23f1124ab1d5bf87f3aba418eac28cf7c31dc687dbecb6" },
                { "pt-BR", "4a91deda3fb30788904d12465dac98aae38d440458afe59ec7e9d495f034efad245d79765b6bb9d47173ef60240c4e48ede8daf512da1c835c1ae87280764d8b" },
                { "pt-PT", "7673fd5b4035e660ae55d5e79294da2e16ef280a5d5414fee75f3371807029d955794f2c88a381507bd21f837a925e2bb975262180051b80472761835525a59b" },
                { "rm", "6dd6539b1263cff60f6a4d06da2edf3de486e03d6e444dd73992a9cb1abd89b165ca3dd5b706153ef901b9bcea5512936c4baac1a61c55fdcd17153ebdaa5eca" },
                { "ro", "c8614383b362ecc00dae595568af319a38cda60a58ba8d11498c5a083fac961e67b2ae2b73a82a4926e900a01c1ae67c813f3aba302dec3a3cdb221810c142ce" },
                { "ru", "c405980c2a134c42339a63af9014fd61028192ce0f165937898b04f488f1f675df8da14f3eb9ab18e59def49ab20e6e9a40285d03bb239a5e16eadc0d039f8e0" },
                { "sk", "b70f1c77ec7b37b53d384078402eb7ba9220be622b5109aa8fb0b656dbfb7bb7ebdeb5521b48a1c5742daf5cba2be10256494d9b87db3b9bfce6e35068e44b1d" },
                { "sl", "50d99ac12c0e325fd70fcf777b05290fb13fc56461e51c8a87b4a527915e06d098e6e1d8b609d53e4a3b508f91dbb3653730ba844f6ef5fce15c659ee78c716b" },
                { "sq", "9d18660f71e1cff9c03c924e8d32b49be7cdfd8ae48b37fed0d6aabd3bb2a3f2da549df2104c3f0bf8e4832f1d89a7075f74a05ce48d128aff8d2e51a8036061" },
                { "sr", "bffcddde74f6f831c05f1515eea671ffa4d98768bcb868583d2c6449c7fa3c96c5ebb1ed6cd38c0508cd8ba2cdf2093c60e87f0fd67d330cafbaadeb49baada5" },
                { "sv-SE", "1c530cb4a2f304b18b53ed51eb198ef9988343d1b870f871a91ebb2285326c598ef5495cfd2ae32ad9499e9f2620eb8c3937a4c624e17ecf57233523ace2e841" },
                { "th", "b1a186868c3dd4a03872bb197f1d801f9bb00658b5ac4d422994ef535b58bbaae66f1dafa4a412908a4896985ec2a5038f1f83bb26e314229be70908a0810aa7" },
                { "tr", "75638459b09710f95a9eae3e8ab858426e910a800a0d1cd76e4e0393be7bd605a0eb5c02e558bf32e2bb015104ac7b69fc35e6791733e1464b56861d7a570517" },
                { "uk", "a3fd31cd6a2408d3b7a5059edfdfaff1f35b174ca7c89e193e11f9231a1f5e7234c9c6857cb0f9624b30cb9e5adc9154e3cdd84bc6512c39c4ccb754b3ab0eb6" },
                { "uz", "75591663f20ef6d8e72b4642d6b96facd2f1552d3d460d78aaf7598393b9519a2c0f22f8667175b0198fa3da87afac6e124d3be4174b9952375b08ffb322e9fc" },
                { "vi", "f6075db16ddc4d24cfeeeec45fda9b28e9a52d4a70d8af17ff23500a3437491252916759efa3b03a41c3dc0368bc1176a8b941dfa32ffb46321aa2587feb8fd3" },
                { "zh-CN", "ea895c31a1abba5ad49d10926e15916f5a9fe5568841557776048e2f13f3a8d6a201527c4820607c8f11e592882c4dc739af13300a28ad4f7b881301fb34c385" },
                { "zh-TW", "cf348126d985cc107b12ee2893018d433bbce8ba429ca2ebb47d8230058b2f544b6fbccc3cb0152963cbaa848206e611b8aa01de944c4457c091e5f6927d2ec5" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums32Bit();
            return d.Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            const string version = "115.2.2";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win64/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma"));
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "thunderbird-" + languageCode.ToLower(), "thunderbird" };
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-latest&os=win&lang=" + languageCode;
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };
            var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            try
            {
                var task = client.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));
                task.Wait();
                var response = task.Result;
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers.Location?.ToString();
                response = null;
                task = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                
                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Thunderbird version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksum of the newer version.
        /// </summary>
        /// <returns>Returns a string containing the checksum, if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/thunderbird/releases/78.7.1/SHA512SUMS
             * Common lines look like
             * "69d11924...7eff  win32/en-GB/Thunderbird Setup 45.7.1.exe"
             * for the 32 bit installer, and like
             * "1428e70c...fb3c  win64/en-GB/Thunderbird Setup 78.7.1.exe"
             * for the 64 bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "/SHA512SUMS";
            string sha512SumsContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                sha512SumsContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return new string[2] {
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            };
        }


        /// <summary>
        /// Indicates whether or not the method searchForNewer() is implemented.
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// Looks for newer versions of the software than the currently known version.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Info("Searching for newer version of Thunderbird (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if (null == newerChecksums || newerChecksums.Length != 2
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                return null;
            // replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksums[0];
            currentInfo.install64Bit.downloadUrl = currentInfo.install64Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install64Bit.checksum = newerChecksums[1];
            return currentInfo;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>(1)
            {
                "thunderbird"
            };
        }


        /// <summary>
        /// Determines whether or not a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate process returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            return true;
        }


        /// <summary>
        /// Returns a process that must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            if (string.IsNullOrWhiteSpace(detected.installPath))
                return null;
            var processes = new List<Process>();
            // Uninstall previous version to avoid having two Thunderbird entries in control panel.
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(detected.installPath, "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the Thunderbird version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
