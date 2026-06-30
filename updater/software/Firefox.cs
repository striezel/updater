/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020 - 2026  Dirk Stolle

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
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/152.0.4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "dd5070d2cc090b8a7b8dcc326a1f846811de6d459bcc739f235e15d7dbcbcd3c9aabbac621fa0fb1939e72ba989db48ccd91e1597ab75d7e0e1a54c62eca5111" },
                { "af", "6adc1788d475efa2663be8ade62ce7a69ebe4ceaca41cec1e5d121d4e24d72dfbe3130ed2172d7cfc0c40e828967b7210e2bd3366bdaec7e4d490e2c358321ae" },
                { "an", "8a6472a1e18db49e16a0136fbf1e5b24fa09ea924b4eb89fe5f1f4da7e309ed9d0811191940650358aef1b2be44f799b119ee58b1653274e13490cc3cb5b4bed" },
                { "ar", "834c0322c2ed9257b22c2cac557c678dd11b77c9014f5548812d086229a2d17f876ddbdd9ebcc6a6e835b5bf3920858da0ad0fbf2fdcdd1464fe0fa00801f6d0" },
                { "ast", "03e5679ca5a1edbc2502d9522838694998c6643bc38783d2792e655bacb65c7895f318437da45db028a6efe09e5ab7a920e3a535ecda017289ce17d2527ca899" },
                { "az", "3f3d0e1a5659a0f9e236827bf4f88b3cd581f694fd5ad21f7e99105a989e278574383ba6fe0028245becd797680a88f01ea6d9c7ecba17bba7e64565eec7b41f" },
                { "be", "9ba9dd38444728be227b3edfd59af78fb195a30845f151688a03a2549d999e0497058cfa8572b18518f5adea9d287ea6045cf31d372dbee51a7a74a92c7dc4a8" },
                { "bg", "50372a8df4120417a7d3b537d027c8399ee4ba428638692c94f3a78905cd7eeae70fe8cee2f4ee9b83541267ba6f6b2f367a2970ada90ce50fc5bc1179b46204" },
                { "bn", "0e74d9a804cff30530119f43ee22e14bd9e8b18f9d8eec799a025c160968bfb25568866b9b7c11f929a0114a5c681ab6c8a908fd272a9b5b604e8493e5792ed0" },
                { "br", "f8c4d6f7c86b69bb72daa9052a8e5d08a3c1625029ed1c82044737624e2e46b4807418c3fb4aad069a9256b6a09ff941f9a338ec59b4b86f2814c08026dd1ca7" },
                { "bs", "1fbe60cd5ec04f3417e2b45fde69026540bbdec31cca132b0cb84b177f63b001d875279d915610600670e651b10c1cd9e9da1a6479b4ec29a6a2553795529f6c" },
                { "ca", "ed67a28fc43b0f48f00a99afb9f22e0b418a30eef122e987a744f35cefa731d02a8f358b7abd6474bc43e6935763470e63df2c5f243beccefe82005add60f704" },
                { "cak", "b692d6a197c30e45d5dd4a094cf4c63fbde9d09d588fe0473037a7b6d77e2e680e51fcc96718a8031780424c22d1c73bc1932f1d8bcee29d7be46c4ed29e3623" },
                { "cs", "0505415532e86060ecb17a4c3c8338fc8cff9318393e4cce6c9761b47798cfd327f1477d9da03318bd71479e81933d0f2937f93ffad2a643b8c10efe35bf6af5" },
                { "cy", "27ffe5c8b8b59810a2818054b8cc61b06223e9e90f7dde652a0c33dbffe68dff5de44ab57ef887658a5c4de93b7728bc4d20afc9e59127d5ff2ee84903e55b77" },
                { "da", "99e4df96f894dcef899eb6f18aa2b6189c63d15ff8018fe94424bd60d8b48132dcb85d17e1ec4fbcc4a6859e53d7a18538288d38ac7984702037318806e2ed1c" },
                { "de", "97468888bb57d798197f7d0459100240fa5578e9c423896296602c36b90433c56e17266650fe85301fbb28e3e4a507c3362b47d8ea1ced264672d0fcec80f80f" },
                { "dsb", "d928574816807b0cc028a2ea1546758f2b079bb3ac212134bdfac6c306e18f2e1551f7dba2da606d918f2175e9df4ae3f612d3632fe4e56a022541572e9e7ce2" },
                { "el", "3157f9bbe65826c913c047f3f1d830f837ecb92affeb91476f07de88ff76eb7fa6029f5b74abd721897e8e62286e2f934988d8d29de23d1b2b93d0177b4f21c5" },
                { "en-CA", "14eeaff42e049aeafcc375afa061f5116537b504ac2735cab639c881f1d0c2afb95d5cbd78d6e8b1668bd1fbefe8f222954892197b84784d0bddab950de80a4e" },
                { "en-GB", "cdce37624a4b7299fcecfc3893e210004422e0b4e6cd202405a85e5612c886e63754a7af080fde83bb21935a5f97ff3c88d5ecb51805bbbb64e1e9380295e3a7" },
                { "en-US", "fc5509357fec5e0329ceacae0ea169293fc25588228a37622ba5f5e68b87cea4c8eb36059b358406b64070c8d242f0cf9ae82cda60f5010ff777c712c81297ca" },
                { "eo", "fdc3fb3f48e5d46d332001337d57349d955589fd42e89867ad9fe36c3ad04480730b5b66203f72043fbc9d89ae0c7b2db253d98adcacb348ef4951e73d9941b3" },
                { "es-AR", "5a0d7e7ac8d981382a787314d5cfa17618b730f00e05e5c2a76a2864563416500590ff105775c233678bbecb9656a5f926ce5c73cb25fd1739e066efe992c5b0" },
                { "es-CL", "9dd110d0276b5d402aeacf84aabad285dd3b566efd1298ebf9436635f5fa78c639c518ec094d276269b730422f078f2105da1276c7fd1f14beb30ddf4db425fc" },
                { "es-ES", "738e0c2ad61c0ef2b5955603872fd3c83421db8a76a489830af98e29fe78b27fd2a69b54385431efdda2286c3d2dc1baac2772c4d2b3d5568f60f935f4e0611f" },
                { "es-MX", "6519485b2d8e8889dd9e131344da81a4332a6fdfe9d7953c3be155e9ad8e55c8f6efd7623f6597e99b128cac1b5e1fd729d3804206f019e8bd49ad4b900cf2ec" },
                { "et", "9a5fa7dcd74eab4ed5a3b3d381fb2d8ab95c7ab3437614f96018135d7cfc8ce54022c952f68bd68b382420baf1d1de841cfa523f9314e0f166bdd7ed8ac0a01a" },
                { "eu", "d2da8485de81d1b5ad6ee5c05b51f523751a74d8b645dc89c879b9ffd83d5cf1d039dfc36b7f6b84d041353f5dc4d3371056849e7bbf72edf0da847a73ee436f" },
                { "fa", "02f797a05f9e081bc5226409e0ae7d679a88eeb39fe9e6e944a352f6c1ad5c1ae41829accc33ce912db1df2bffff2ff9dfb14f06f25bd4a345766c6c12448f8c" },
                { "ff", "f1fa73368d8609af5ad41fc54a5cb0a25b54ce7e1787e0b8cd5ca8be5b4b7703c012c9e5408ce07a5d2264449480d2d2441351592800fc60b72a06bc299ddb59" },
                { "fi", "90f2961939a7db2c3f532be331d8602178a4468ef0030b505a5a2358b2e70bf497c1a50cb0ae92e2fd31eaff61b051b03aca79e28ac899afae27160bcd39d8aa" },
                { "fr", "96603cd392c8a5ef2486014b2a6867fed88489e4d0808ff3ed0ccef3d7cef234cb32b255700c8fca64449211b28801cbb0686253de34de16e0814b53ac9ba3af" },
                { "fur", "41e220a8db93b38fc904ed1a86fdede6396a3c363a627af38a042df804f169d66338f38c408a987d64981a7e981bbd7c41f91cac8a4f0091bc24b2139b88ad52" },
                { "fy-NL", "06fd1def129d1c7419a011255e8a3e4b0a769aade682f341ff6776971b3680f98d135ea54fd778b6ce46cb215295edd7b2c7f838c2f16907861cb32ecf5c8b10" },
                { "ga-IE", "a4ffd4f0cde5b269984bbcf36de75c45b145e2add2527ad4e24cb1fdfc111a87586544fbb891edfc3117de4544c0a1073c27e56dde8104241e1c582edb2bb15e" },
                { "gd", "61f3a132c434f1293dd69b5aa89cf3fe11dd8b800506532174c07d72c10cfc801ac27212f3074b6df4c845ebd55f246a77aee141dfb8515a0453d3dcc793be01" },
                { "gl", "fe417a00f936a75394d3ee1b81b7b1200c9369f8e5a59952a34943e912328414ee607119fc4f4efbaccbeedcffabf6ebbaf6fd617eb901b774b22d343db4b3c8" },
                { "gn", "1cb12e2718d636b58001cbb90828a4a8163b23a12c14ca571613759d2e612501e01bab3030004ac957075f186548b49aca128fb2ac507005d5a372d082a04bf9" },
                { "gu-IN", "98f028e78c3a23adba0531582ac8e84492c43a25a31fa2ec12ca0eb7b9727343d58450e14b8eb36b3caa9ae3016714d68ddc002e0c4cbf3ab39383d5991ce7cd" },
                { "he", "0877895740c157e301fffcd5d5e6432439f918c8f1e2c78e35a00302ab2b9789b52dfc6ca822c82ed94321a801499227e52d1ea4706924d729db1fe20a4d46ba" },
                { "hi-IN", "837ba183a47f504d62fdd6da309aaba0d3254cf04e8dcd904948c3fbcd9086e23b7721437559f8349784a74ba7d99458826e57fc096f3fae0518f6f109d9c5bd" },
                { "hr", "95b8bf2d8b4880d0b2cff71c91f0c8a130845a47dcfd799d1b265135a241e77c1c036024c2185b039d718cced3dc720995df7ea75c8b3f916421a76d3b29c956" },
                { "hsb", "6adb241e7c80d3cf45c302dc1553669deb9a4485a12f0d9e9f36b218f1ee44bdb13f00ce20d902976aaed073e8ad7c54ae3541da060ee4a315bbb769a52d2cf9" },
                { "hu", "c966dea2c8e7b0302b39097a27b267b0654f18034ab0ab4c60a02278750afab1eac24281fddddd5cffb2af1c722eecea2edb9c73b29ffaf43cc090542ff970d3" },
                { "hy-AM", "b5241d44ec264482af842a8bf8186c24f4dda37ee9687d988aaf3570ec6ec87ba32c82a38d429bc5e0d489d4933908da479f0e3fd0f32788cc7e6d48d2472081" },
                { "ia", "d30a1a76730d427a2bef4bdc4376ac8a4bcdd9e6937e96e3b638103a93c76f0037d50da98eef7d1969a40a206d139813e5431bbc1f6835b6f894bf79e88cad8d" },
                { "id", "0ffaa174bfd75d86ddcbfd860e486379da73d260091b7ce4f8884e0986e133113dbd35504037331afbe82cef12cf1bf3654a27b4cd93a653d75ae123388222f4" },
                { "is", "f5dbbd9a68d11d7f104504cf56a6debf26f8a0960b103fbc69d2d3edac77c41389c6ab02f2c8326f3f9b7fc39222986c1d5d3e32debcafba3030dd129b3819bf" },
                { "it", "18666ab99e195f45652270fc74e3ba2d99542d1c03bc64e56b4eb60f563c5bb05a3c9f808bc26223f9fbfbc4ee40ac630014a334d9615c0f2c0cc658ed9c63fb" },
                { "ja", "10df683ecc9c65ae6cd5f6f1ff937395ff23d704c633ab2950973fc96d8933865f7cc2c234a6b9e2bb7ef2b4842850f3d37978309e599fd741ab3f63834b5a12" },
                { "ka", "dd990853eea4d3fdcb5187f44cb91ac0e24724e0243f2b326282306373eb9dba85ad339d92280add291c0b22a5096c23db749390bc61fd195b5e333aa3b003f0" },
                { "kab", "a42b7f3d1d9cc4a4548c9724a26350f8c9ecda5bf276b9357a2723d216aa8fa9c015137cb2e6ce97f899d4cd129b0e948bedc4f32e2b5392685adef6301d2aad" },
                { "kk", "0b2751d51661b96da60482f4bbbbef824b6182f2d8105f74e87d0e2c393531e84c96822f50873f0c152c5e86178cd197e20a3b8a3605cdec8e9e469bf4c78cac" },
                { "km", "69b5dc74607a28e5ef3716056c9af44865970c02effd439b0bb18020bf8b835ea400599e0f74b4fea31dd699fbc67699472bb369e95f8a56a9f0f7d7ee289dfe" },
                { "kn", "2f6d997c660c83e34db464583dd54717b0c83b6a39fe80575fefd1e740c2765d05ae8c6d69dfbf0537d8b31f62f715cb460fa09e159e8cb7791d059be76cfaa4" },
                { "ko", "7781f944aaad0ed35e7002dbd57d6dba8c194eaefa5ec6748bc77ce2393fbef1893a1aa2846d64c3ab068d858a3cf4a5bf43953abacdc588d772da6997e10314" },
                { "lij", "68de1c59cc6a8866ca3eee4f1020e560b4ae0cd3b497df31c960a20442d4330b8fda44d8ae0651bddeb6fa17a67951a63a278dfed939176b17387fbef3fb0026" },
                { "lt", "662e6c399bc5fc81ac58acda94fba2b81b592d3eeacd3dd751e11caf4c55a85f98c586c2d112d84f5f8575afd5fc5a07f3e188fc8bc700a232c66a8ffb1a4403" },
                { "lv", "2ca22fc45f39fbd30af65081e0cd35705f02c72fff4e51402c03799ac891f169e8c2518ffd4b9182485d737e717e08a99c4b9f73879da22389620a252e355f7c" },
                { "mk", "2edcfa156aeb06beebbed2b19e0d01d90826c38612bdd172ce9b183480da3b03aa2a0e4cee93d14aac0f1d8b6767d05cbac354fd9a0e88379c0e1819b7f33c59" },
                { "mr", "322491b403230040d254b26435cca257d6a4b09acc2172f8acd8f25804b8277f7caa23be5b2715808307726f5ab90370d147c777c9c7b4d136c6bee198a94e0d" },
                { "ms", "c55c3b7880955eb3e7810c339239cf3aa62a20087ce4790eb543f33bf3ed007c9489a353cd3758d8a4d2dd561ced5654e91d5ede3ed78f42504d38fb80f632e6" },
                { "my", "eabec233979e47e75785922c08f7aba829545e4c6846505cf53db891a70a724469aaa298a191e995a86bb85ace2f5c204a3ca976185759d40ecb18f4ff29fb52" },
                { "nb-NO", "4ed69f0117a06a11b9de515f0821722abc3c96ef265161c50b94c43131cf7b21436f06daeca290138730d62881b5ac8628d89d9bd015580e54e1846f54ae509a" },
                { "ne-NP", "b2054057ee71e6136c8cd4755db446653f38ee3797948545ffe5da26fa7508a3c4f28fd3aa03e72ae6f14207b625d7cd942c3a26d5937394563ba22dc10e6237" },
                { "nl", "71d856d73342df533a6b852fc4decf4fe4474d8d9cd233dcac189cedd05dc495a56d9dd327e87390ea8af4fd5b37b22c911439883d5d156ed2375b47257d01ca" },
                { "nn-NO", "38802729c9d4af1a4b367cde768636ba055fa4dded45941373f3a66d39292673d125c6a5a314be1d2fe7d79e97ae93b84804bb37873ce620eb060a92721f137e" },
                { "oc", "6ec27ef93e7fc2c8967968fff0d1a070a93cafa13b9e68f3dc92b6facaa9cc225c2f9131c0ab09277d6c56cc7dc75b83690d2bc87b361146c2dae4bc23e196fc" },
                { "pa-IN", "86ebaffb44805b4bc4f96925a52d5296ac613824e6d13f71a078375bfe86973fc40ef8dc4aaa441a455179b38ed5fb1af1b8b738ef5299ec3b9a16d98278749b" },
                { "pl", "70cec0ba2c4c805bbe4b21b2c140674dee65c621a1b94f342e9882da6b5cf541b5cec52d0951d6b222fe43cbcfa9d19698ec4129fbed66160098c7ca667fc355" },
                { "pt-BR", "70d4f779b68593fa1b66be8313e8b4e78086be3791254a599288e670e2bbc93c90d2dd739bf40cddb1ec41632da1af26804b0db51ee9862d9bcc7391937d799e" },
                { "pt-PT", "24b5a13b1784ffb64066201558d54b8625d3da8555a1d337f9573aecd46240367a88c15eb55bde1e0e4b82e41948e35c9cca6a693e5d700c3cbd0eef6fb07e28" },
                { "rm", "c9d354c8c143d26bb89de809dd64cc6042c8d860ba40fbc034ff4bbc7bb32ddb98c4bad721e49c212db4c10225e7a2c9b7b263300bdd2d29b688428e38b9872d" },
                { "ro", "03afd7c4064943219d65c93725b8767ef827cb5ee3b6f87743e35cc30f49f985315fcabd44134f4404240640c0bfa915a2b021ae68e98e82eb6075bd5e90bf0f" },
                { "ru", "881c6d2b8045f7f5f467faf460aa452b59efb7f449682cf7e0c61de1ee722a4b9a0dc67776f0a300dcaac90bdb80f7a44b9019d45bd1f712a41922383176b0c2" },
                { "sat", "2d0155c2f8e825a3bf6fea9483f392a7139469c6465e16655af82556be092e9d89a3bbd70fe7d0911afc488a351a6972a5bd5e6b3674f042c86af963bbbe1875" },
                { "sc", "03653101f125d857b6cc6cf67c6bbf83e783583687193f9aac6bfcada30ad18079d9940e0309d59671c4aac07266e2177bf513e6cb7f5b3f5496339f6fa004b3" },
                { "sco", "c13412391a2a2111c67ace90c9226975e5b94803d2bb406148894ba862711d30d797c8dbca966f557470a5dc5fdce9979d8ff5feaa014af64ba3c64db088b1d9" },
                { "si", "8179101ff0950ffd9370506e9dc2d806caced1eb9fe5657a27417cb553a9314a1ae0c0332083bf37441c7e954b6572f5d4d039141d88e6f4f67d758f22ba509e" },
                { "sk", "fb9afb6fb5cbb95b70fe2cd48f79f832012df019c8ca22f846468a9baa7c493d58850a9fd9a0323f6c984e073631ff73de5f78a1bf5142a69eba565fc941ea54" },
                { "skr", "df4aa30c0b9cdecf61044e2b309644a94df937b611b94e0fbed22d42493cc8c3837f25e2df4fb049fd71b35c10d43ece0b5e723a23cc0c5a02f6fb45ea282447" },
                { "sl", "da0309f3227e601b8667e4dd2a8c7e48e9646f9ae404411190d22f00eb6fa7b3bb4c1f24780f9c985e09ab9ae9e0a772d0555a95f03f4f19e3ce5982a3c4dc13" },
                { "son", "fa1c0ea21e5020f1d6630073209e7265fca020fe81c4938ebbfe49924d3a8bfef014e990c710778546ff750b6e53ecf794a8682dd7541723132f44a729c24e30" },
                { "sq", "efa8303955645536bf85506919904310224496c3a82637cfc791264442e40f09a935bfed36a5e2621b7e7afbcfffe0f07e9626d31747eb5cc4cd93aab7e035e8" },
                { "sr", "62329db80760a49312cb26005277a780dfa27946cfaa7d77bab93766eec51e08c1d0ff349fbfe9d9b8f038a3c6289af7c0088ce2eeb1899e4e5b144051c21979" },
                { "sv-SE", "27e917ec8fcb91cc38bcd84b018f909a9f6db2b6499fa82ccfef2111496e332763c6cabc1ce3b0b62db4279e0368c88837d32941c7980919761216de7cd78404" },
                { "szl", "6f78a54f1343234eba6e2b20a2c709bf71423ba4e70ff20d6aaa3f400fdde5a1dfd9668051b631c1f4f1432a769b43232b549c18d0a5811927f9299139207ffa" },
                { "ta", "d5c44da10edff8b617ff11479b34f4b146c7db322d9a47457d56f5cc7ead0b8587cb6d0b9d7279d131f0a333ce7bea4066d4b80935915ab32e8b6cb0a672f117" },
                { "te", "b0d16ecac899508dd67ca62697a024cacba38c94313b59840ffaf0a2e8df7288d2ed78fe0ed1ac2c84c9a349484b83de882bb32ac8c02bb34b635ee1d0f6f880" },
                { "tg", "33278ecc5b317c42b04d9e1ede29fe0bcd86291c2f8b4ec5845cecb72db4cda6852157ca8d0e6a60cea41738971bafedecc474850df5f2c16ee964bcbe980ef8" },
                { "th", "e74784a10c54e8cddaf4e2fb15c2c59b0a2e5dab15c37cf6589ec9a26640006dbf54889d6640808c42cffb6cc2df8a189c40319840d783e9f472e2b86a499140" },
                { "tl", "65c40ebf5195dee208d3ce3168dac2e9c161cf3cb6885539fb2484b94353ea46bac7d98aade72a158354e39d516465cd08b8312901dbcdba00ed5ac836939dc7" },
                { "tr", "e1b8603485eb467bd8fa0c422c74f152673d4b102c097d050447941c502ae066846adce4a43e4f6a0c54d3ee1868135095aeb416c462343459418e3e80a5cf2e" },
                { "trs", "d09b976f81bd637ed4ba7f541a4b34dfd6b843a65c659b96bf9e1ed2923b38f16f7bfddfa14790d2ecca02f81b120b32b9af9cd60634b1d2328aad5f2e2d9c0f" },
                { "uk", "c4fa8248c4f24970ca2e0905450e1ac92d56497b5a72bb75ee51a7cb7959a6f4c44fc454cf28928b4f0940373385b78b10d920be78daccd3323f405c369646df" },
                { "ur", "40a41e57afc863bfbc5b577ce0b53e88f6b13e321af0dcf2ff7c75e3550c8ab0ce08e3472d3f02d3328a46d8c47d608e9e71d74e845e6721cb901d85d27f05c3" },
                { "uz", "c18b3135410c1d1f0a6e6a8f82a48074656307601c8746362561e95c20678374865fed144eadd29740b3d898a4cca5b852d72532408f69dd689df48ce99d44dd" },
                { "vi", "93741b8b282b81e7ca2c7553e2fa67552590725507eb64035ab0b579cf9d944bafe115aa7e0dad08d00fad62d82a8abf93cff6090d7da0b1da1e608c1f48e7d0" },
                { "xh", "005cd9874dd36856912502f87c4737bd9dc9af48a23aac6f878ce28756bd419af6e242b88f33610a01f7f9f3e7c3ca2aa8d41cf87a5007ffce3fd51f2a79de85" },
                { "zh-CN", "3b726a344165561290b55b5fd7d9310298228b9b28e5966afd5b0a86b54a4f5157da49f8cf7891d43f014602c645210e78ce6cc501d71a20ee2972479ba1fc67" },
                { "zh-TW", "aabe73a66015855a2c6c6b378924c4e604de7a266abc3acf6a70bb7f9739b6b19eef583527ded2b916a1d0aaf11f3b43bb5febec073595d2547eb96dbb9f1ce6" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/152.0.4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "b36504bf665c324484d7bceae1865f85e0d2af2f67d7ddd8da2147facf7052e838cc78cd0843e4983575ccb11948629fb5d83c21bbd3b143d0cba836a8d8e878" },
                { "af", "8e72639eb73db613361a4dd8505cab6c63a7d5672c6d9221709cf7fc895756076f7cd59634540afbbf88924a4fda3958d4465a195cc52030a7523b57d734224c" },
                { "an", "41a91af7de7ee369aaf663f9c944426387be970e53e24074fae9a9d7571ef28ee099c4b5b38bf62e2d84486179ab6183ac5b554cab943be5ff5425c0706e632c" },
                { "ar", "d70c8e6e37aaeddbaceb2bf20c930130d238a7700950b3cf47b12c8718c136d28f781ca0ec5334531f22fd21096d457c888df73b3a08a212fceea72ddd32687b" },
                { "ast", "4be408f9ca2962ff6076592abe64ea99d5f0fc0d9999a6574e6e21ba2962b531d5e09a9eef3972ac5e40034be160b28ad318c7ee79c801f3ec664e2c272b3155" },
                { "az", "c8c6892c763bff2f8bb02d382f14130ca738489f0de03b531e5d6d8b9e9feaab13ae6f4d77800bbe62e25fb6ef3efc041ed6e813c139f4d5b735cde5bc920790" },
                { "be", "206e5e18d7207a07187ef7f4e4cbda814f76dc44c066878d9079207d40f2f8fc99b70aeb423a6c4f455f31d8e4ffb0889e67436ce037cb3fef64fa53803012b5" },
                { "bg", "c52c92437f11b587fbc20a0131ee9a1e6ffda73926b8f988ea41f76f54fc982bfd33ecd744bf62dce593bec0f86f943e163f9f3589ed7fe1f0768d646c4bcff9" },
                { "bn", "bb26b84d5e60e9848723d83e929572cde18c04cda11c0dde1609862868413224458bd79685929fea7b8f009a71662929c1734ffc87e9fb36712c9b4d51de130f" },
                { "br", "fde505bd86c8d1c6b0b6a7faac7d927e64af2dc9491f53b6ebddbe1b0f94f31fc9a1e98fb71ce920fb39a29307085368b3b123e1675788bc224b9ab0e630697c" },
                { "bs", "6ff30628aedc6fce79d5e6ff3c365551fe291d431bac743c1035bcc5f1c5e43c1b93513e8d6f86a829c325cde27c0c077baa280eabdfbfea0d009954beeae57b" },
                { "ca", "0f801ca1b230b1313c8fe317a8a1662c6ca2cf1d412242b82cd78bc6ed84d46c9230916d32a27b20a23be70ec55824831c2a0014f9dfc3599574eb7d33ea9d4f" },
                { "cak", "a7a6e584d63051cd941af11807b5ab774f1d7c7752f9ca8cf2099027400aecd33875dd601de22fbb5140f47ac611c582076291f7eff2f7143304ed67e54ce7ba" },
                { "cs", "6b68e61c9e04f362a2ba1e449c2b68e78490d715890cd428cc0bfa3223714958e18a3bb74f247ca192161bae1abeec527888d7365f5e305ffc08ed1bc7978e03" },
                { "cy", "e339cd449835a533841cb30ab099343b5f90979dee21efdd1d746b8d10413c7dbfa151d6735167ef8df6e79282d7b6df533e67259e6b05c02b50255b607ba7fb" },
                { "da", "a24a0a7fd01da84c1c8585bffa711b2b6bd6213c204f51d8231540f2fda46819ca78038277c7c7823d0a2442a403e88f07e0c35e55d2805153655b37ac393e3e" },
                { "de", "d1f0d08fa17ea7f89519eebb471460b4fc239bf46a2546beb67bcf4cf7dba49d625f0a02c9e7575199dae52558e839a554df0a610acecad4f287e3ea0b41eb23" },
                { "dsb", "e734a5c511505ce8e938427300aaf0887ca6ca4d6c37551ebd941761aa60745fe10940cbdcdabf007e3449e4032baa18829ed6db7b66d1e2fafa3a84adc4424b" },
                { "el", "4ec0e4e4d9112ed6dea561c87ef08433b54170b95788e03791c33fad80b421461bbde0e70fcc0bca2032ca1b2790d50899daa70365fa881aad40583d2badc416" },
                { "en-CA", "c987eb66893969fcf33fa1c04e9f134e107ed8c18a7e40cd7b6de066adaa3831eabf2c085c89eaa1abbb880b2776ed96fc139fd835da30bfe2036f643e5c2e76" },
                { "en-GB", "92a8ad1e5e848c385c0ccd7496978b4593b0e79392862ce6f96ea8efb66c58e184be3d6677a9ca5ffb0bfa2395e715e8831a7576b22db2c6e209cff6a9240e59" },
                { "en-US", "0cd81f62f658572ab41cdb47ff1a0a0d184ef1a19dd1577ca213fcb5a2843d8ef9ccfbddebcbdaa8455ba5c6de2e0707736f54a0c2d8b4d7fceecce93d6152cd" },
                { "eo", "e3c6761378c3f9a15689e93f6f9a473c12220a981ce875a976b7c43b90698e95620d255fa445ac9bff8ee95eb34ea1219f7141ba97c126a77aa24ca189219e56" },
                { "es-AR", "91cb20bf17f96c490f0fe1c5dd67fb90e0750154b3802eb4c3f3a31a16b44899f2f2a582463fda8ead75e4cbc504cf06ebb450df137debc606b831cff96ad42d" },
                { "es-CL", "7dba6614b36ea24aedddd21875f5d656b9499c6220dab98501ef496b348ae4dacfa12fb01c082e8792b32a4348b561375e640d5a38bb131e21665a1aecbf9d36" },
                { "es-ES", "ffcb80013574809f47cba4076ab2afbb28e9308344d3e229b0cedd11186761d97d620ce0cd33384eccb8273c87862cd2d006db9164940c8aa14fb8953012608d" },
                { "es-MX", "140a7bba67ba7824eb60d34aeef15cb973f0b6cb588c58e26450ab6ba76ec30b624929ba84e2a2501a46ca16125f787001c4f0e0c512263eb18d0e0568c60a0f" },
                { "et", "9597dd4ca58af256951aae87923716b3e4e5ef3407266657d60c0b78f5e292be71b1b6ca390c31d16351da08b2ae1d1825b850033a99633fc124d7d396c2bc41" },
                { "eu", "3bf1999c4c303e0c6e17c80a91a4af93d3f0d9d5667ca0ad50b3d62945dd2a115109114ad900247411ebdde8bf63f9ce4cd31184dfcbb64592258a2130283449" },
                { "fa", "87ab12999846e0d7c37c30bcfc4fe10af47ab25f520da7ab9ea0e5a47abc037e4d72f8b4d615dfd98beab04aeca0e3d07d5ff45563e8f07e3b4a18100ba09aa8" },
                { "ff", "6352550c2b708428a3cb791a8ce8ea519bb51d1f2fb15cd4a91a755206a7d30cd4aaa58fc92586d4a1e258aabfbb3629052487a41449490dabe3c460e990ca2b" },
                { "fi", "ed1ae984dca1677f443f7fadc5a6d55614e00d207131f07a263c120788467a6c7f0b73a341ff3fc91958750f303db5f41297815a359f13d0ea298daeb84a3d98" },
                { "fr", "62d71971e66bd50c2bdb913a9953ba0d2645b1f2cb00d0a5f20339c2286669be905be6d1225ee06a19724fd47e7be031e7d91105965dce15594d686d4bc782b8" },
                { "fur", "41ec91c781561295653e472e462c3c8052ff3f4c541bc9d6747ba7d276701417ad82b570c0a0c9ff4d8a600b2e8c2754532ec932f51399837a94ca979f70c915" },
                { "fy-NL", "288e89ba1735928e1e794d7a94409509cda9092e22b21863b370cf157ebd056ecd44646fcc4ed3ffff0d81742a7809ad2a223ab51ec148a2e3453656786cde00" },
                { "ga-IE", "111c65729100685da832549227e090f6ca99811cce413bdf1dc61711d0fc5bb8087df3c808746aabab25ebeb5d1c5e2265c1606a46bcefc0d0d69ef9e3651ecb" },
                { "gd", "28ab13693855e9faf530961bb720da04d6e44b788b40f55df7c1ad85904eae27d2735b480c1791a48ddf63910f50e2de1ccf20bd41cf5c75746172e1b0aec640" },
                { "gl", "96c85bce495ab002d104a85d8977e771f2285c5281be98d551806f4b4ca6c59bd99bede0628d6332cc058f9f793422f80c4a0c911f1d645748f018d1dd033307" },
                { "gn", "e0360898d999798e621eb048d31c2e1ba970509640aec88980f97d0b92fdcc7098855e1a5b27c617fe8331883dffd0e54808a56b84a93f5bdf38175cddc05db9" },
                { "gu-IN", "6b01c31b9bd869dba3e4dc9037fa3f5903cc2623ec8f08cdacfda7f7147163c3220abdddafce544672f8065231d8cbce42345400116946a31384c41e3ad2368b" },
                { "he", "92f33a800c2f29c91b18b79b28aa435a8d23463589eb375fa46b418e48366503cbfb512393a9d0830900fab4ee0c437316f1cf7e073be60a76a4adc3a01e2809" },
                { "hi-IN", "a4e00496850b2f7d87b17fd5df01ae87bf2c0c6e3d826a430fdba34e554452b7f71fb8bc4deb890ffb4df0226f9e1e84ba79aa37d5065e16aae11e8948b4aad6" },
                { "hr", "5121f684903bff50db4b7c56e569b88aa3853add4703582b4c28056102badad4708eb3977704a2008b80d26b747ecd50f954f16d8473862ea0faa887d7b538f3" },
                { "hsb", "08988d95c3b5615901455b3f9614738be1e8a6b56c5d1ea71071c5406c79e9aaa1e18aff042f1ef1cacc2f6d978945db143e89e869ca4076ee7126cedf44dc00" },
                { "hu", "109a28eeb4d71e08904bd6a9baff10a0a91807d40a58af57244412774101545e4fdeec774f782824f65371b89830f868b44eb1edd3aeb9108135931657e5c6cd" },
                { "hy-AM", "f527f9575acc5e03689265534e7ced78c8f296b64c466192416f43db7a825d76dd0637a7e0e78877556a8a3fa9737e2c43b6ff252834161436cfe22c4570505e" },
                { "ia", "efaf5c59394f3ab613a718ca134374345c843b68a169f245a9589a7d282f84b822970bdb72d90d4f52306316a392c2da60012c1ba7117d4f3db093ef4b2de404" },
                { "id", "b3ed274301c795aa0fed253f4538d93c936c231976ba37b3281dd586c1ec3e78d3784f4a77185ebd3ff31606dfbdfa87b96a39ea4cc825201e8559317ec426d6" },
                { "is", "4337c91e06bcc8051a8744a3e8e6690c7ced941259c69878062842ddd89c0870200b1c63d4aa697bba6bed867c49a9fb569a2df9f0f0f431f80b26e79de56716" },
                { "it", "9c252357c34cf7876e6019c6e43bec9482cd6c5b26bb7a58e250037ad652aaaf27802a5b044522c4dfee00a07f6f900b32bc92f78f68a1adf1c06ca54632fb96" },
                { "ja", "074e187f59e7f9b2fc02a87da0fdc763d16e9644b1f2c96badb15b33872603c4abece8fb0345e256195b9181cd8b79814fcee184a83a94edcf7f9b66d61b49b4" },
                { "ka", "f3e51fafdd5bc1d2a07e0a0090c6cfb1a05a7574e47efd599f3b6864c0299fc343492d5ed2d4a0d7056d23b7bfd2cbf72ba7672f4c2fd03c722543e0eb0d7dd6" },
                { "kab", "a380f6a89cb1244a50b67ff684e39d9e737da100de810a9b1e2aa95c093acdc820eb747c1e1c2cfa5f350a0e99e965c173af23acec9e371b71a82e02f7815223" },
                { "kk", "f255cad5fbe718a0fb35abe8b8d6defcaaf13488894e9db61d585ff9d794dc1aa4d9657b840e982312ea9391263c69a95836fa1e6cb3bc11430d3a0e34d5aed1" },
                { "km", "5adb21b98487e6c8db408c4ed00fc95ad5db891eaa5aed3cd02a93b22f1e3773fdb4c5b5fca029ad17f4d2211eee36f5fb1295f2919a26dca0f6738196f85893" },
                { "kn", "2be304a7ac738fd9c0c78e9016c46f5e9505413dd594a1c0c0c6089a6a7e05111e6a305b145d55cad1ddcd5ff887e46470ff337663c626c18cff97ef86a2531d" },
                { "ko", "81709b6b7e04469d4172620bcd98d562695d097e9963aa1253809f9ad3f0083a823e564effd54c4dcbe9ab668079fec02d3a3e59002562036994e0320ca967e4" },
                { "lij", "3d97184a34eec249aa51eecadd11cde719caddbeb20e0d2d42437b75271b576bf3b9b7d88a6ea13bffab11210f9160c838a6fb2016a2292b87c997840687322d" },
                { "lt", "68c01269d261f5288f0a9116e59c446d2356047bf4a25208b406fb0c3b91ef5e7063dd8421a5dc5e872f2f70d83ad518603044d72093f2ae966b38d7470b92ec" },
                { "lv", "40f398c069013422c790e2f34e66bb78ee592abca5bacf5d514708ddc6f9b556169e1e5f507f0d6a7ff78214b26275bb4b5c5760690cc46ae5f7d5e54b5aeb9a" },
                { "mk", "ec27392c3d2217ea66854297695836e29284b816d6e7600a4ca8cc6306457230b0ea7a5c7ae0ba48acc85288704be7a36e023d9b402fdbbf807ef650aba61621" },
                { "mr", "42ba2da6af6f3408e80b152a9b6e2ed2a5806b64e4f7ea779899526a9f00ed7dc61da05fc6db4645704ee952db87ddff57f07af00b2335b17ca9308153982398" },
                { "ms", "e8785e6fca0f9a0796888429fe5caa42879f9a5ad8ee457f42f1e038e1ccd8974f3ac2aca1d8bd8ddf2d841b7bb42d270bbeabf62977b49643da8d8c6f2e6dbd" },
                { "my", "ea793ea81e597929618c9379134b6835b3692b57f87f1989af8bbfbfef9f03f8288159dcf98551b8197afb1a8336a9d49217c915fd84a767d77ae80890801ebb" },
                { "nb-NO", "425d3e76a8ef715c0bf1a002f8cf5dcefe9e281f22cabb481df899f0231e97f960568d5f5fccaf51c5973b6d8ddcaf9541a40d8597c3c6fa759f9a817ce0f4ca" },
                { "ne-NP", "683669ba09a191aff32279f5fd1b16ef372645141d165363c586363a15a8b8664394757f716afa27a2903eaec98c43d735fe791e502d65c3115a49401087247b" },
                { "nl", "7690927e8192a6dde3fc02699e927992405f3b20ac1d9d3414237ddba03dad357dfc1f958e4f181d0ea8d37d5ff6fba201985a81455f42df80e0c451a36397ee" },
                { "nn-NO", "dddaf5ee6bbf1e160804909b17ea2136437b8ffefc4b88527c49a540ad0f382744577f6efea867ae067f9458ea24f7f03284a521c535164e0cfec38096d4bceb" },
                { "oc", "f6d7df5ddc2b658eabb555b00c0b08e24d2bb8e1aff5109733bf3f0404729b685f93b59d0ae0dca452959e4b8eb90646bddeac3864825100fe29f2f5b870e85a" },
                { "pa-IN", "976bd4634275beb13c9f019912245b653b627db7e3d4f2512b4527e0c9eaa328c3c7b92b68c7991f46235f4649c723c17d67f31845c09f81ada2b4948977af63" },
                { "pl", "7be63b821a0cd77f795fac9c8f84a765840f4c53635bad533baafca9c1a64d5bb855da41da05898e9277e851b589b5bd8e99b1b6fa117eaf6ef4d946c6323c41" },
                { "pt-BR", "c64dffc534b03f2b4493885716d04c1dc8201dc73874b5805fa889b9044bdf4783f8e5684a8400d3175d49369c7922ea4816f1dda9e3c86f80fab334885e6472" },
                { "pt-PT", "27fdaae78054501e60e261feb7786fb09dd9c88edf769fc614512968140fc6e2b4a43f9eef5acc135446bde280f926435a95bce7ba521731b64f21948c7670a6" },
                { "rm", "094e24767ca47ba53f2dccc32b0fcabf4d2cc51e7c3a37f5d8a8740ea69fb716ed436a83edb0a8fb812d3a65648daf3bd6844425d237221ddbd976b0237cce30" },
                { "ro", "d38a3bce41b4faf080157dbd066a87de10dad27672ba064021ae4360e03e9882d27199864f11895dfbb9f1de27e405ff7d26ab5d94eea25da3a224addf6866b2" },
                { "ru", "b1b9d736cf6b43c4a16c283f6c9dc2714c124562de9dfb137cba65c564190987f71aa3ee961ce3816676abdee8ae9995a7b13e5124487b102d1ccc44771a23b2" },
                { "sat", "b9d10c2aab04f40e7311e8c66c46da223f36fa9e4aa7198448b9265d7a91fe5b2eb906e831bca73001a2e1077b91a3cafe06fab58ef6188d188f0fef7f1e27cc" },
                { "sc", "dfbc61e049fdde7d3ea65da669d24db98fcf5d8f8b353ddb7b2bd54346a80ab00b85dd718a1539a001a1767b5b7201d77a544ebe532fe6de6ef8fe905663af38" },
                { "sco", "128a0850c515057dc46f3bea8f8208ad10f07e5bae8261bb4f612bd4dc6812e374239b1e4344667b5a6582f8d89a62ae8e828c8ed3df1d087c7787f9aafbe02b" },
                { "si", "499f06ef2500a1e2edc72ecdda71f7cec5f5b100c0207c3d1646ddddc8e55f2c7e1210b6b60bcc695e67d0c6f018bf41708da158ce66772b718a3b7bd598fc0b" },
                { "sk", "da68cbd50772a90f83b5c9469d7d526f8386ea419d760491e11ecc6258b4d276c1c0a65af0d081208289efedfbf9c08a1b9dcb9f6f1eea320e261b28fd096dd1" },
                { "skr", "d0a9b0fb57e8aca55ca0a785a22f289fcc6cc48a2ed1743d2c8bf47ea5debb12cdde2025f18747a526aa0cf337e950378ae4cf53ca7b4eb5a335b88640a97e6a" },
                { "sl", "2d52002a23586bcb3489007f7b424d399fcec6f58eb7f63897b92d9d9a1080d2d7b70ca282ebbdd3352ce6fe804011b3630f326c9f11bcf8717da30324bebeac" },
                { "son", "3b32b8ee734909e221082a3296c38ede69d680d4aedc5a49e283555e12cf5bf840f2e3fceffbbd413929483bb533938b81a4c49f440d33b96bd0c1b8a30da8e1" },
                { "sq", "2e83418e807476545d9cee19ce75efa3b0fe3fd0f886fd0572908890584bad8640e75a35641a6ba4f3e345fb7b90f096ce5dcc639d5f618eb083df160c5e26b9" },
                { "sr", "c42f37ccba465a2675024942a14b4e306e2370eaf0d0bf5197a16ebf72d184df8462720242038168d7f7a7840c1c0e3907c6dd4a2dad375a514a27fcabbd65de" },
                { "sv-SE", "27bdb04f25d0e0998de5ef0fd61ca1753991c4095c4319515bc228f1d72f47f53e61979269abe6007003d4a7e5e77bd4d427d97c7bbec8b879a81cbbcd62e9bd" },
                { "szl", "8c941101988d4db5e0c19bf58812125d6971d21e72af86c4a0fdffb1087e26c22b034e50ef23d488e23d7578d217d544883331959f3beff3ddd371c3febbe5ec" },
                { "ta", "a00b5fdd2ab80f5b15d3d71e75387442b8e0d16f949c29f86465c723988bba548dcc5e75e1c5a362ebb5af4a57b8f9c94873ce498cfebd3e83b6805f64b9c014" },
                { "te", "48ce238a29f61b53a44226ff4c04e1a3bb9011a29ee2ef877bbd6525d06e998922cfd7eb1d610282461e8050f0f245c73366a81f823420ed9867f767e62f0f52" },
                { "tg", "c8a8c78b2eaf872540b47435153f0d4d2a8b40725db6f2b1ecfc5513406b5aa7a73e086a51661abb268f5da6de8a9dfff90f977ebbf19f5dbec6292f279a6f94" },
                { "th", "ade6e0b3a850db6f7faded92e974553535d9a6bb91394b1a1ac11cacaaa0548a178ce1edfa52fabac82dc03de854a37e68cbc5a2af6124b8e5fa4af6bbc5aa5a" },
                { "tl", "9feda4f8e81e29cc01d945d5af3bde8c7066a56af4b9db933db9d301a47c0e2ae0db0a0d61932846e1d85ec291b4c2124123797f0cfdcdf1eb6f21e423c4010a" },
                { "tr", "36ed5d4786864d709011b4482cc4651bee6177e433e888bf5c4654f8bfba8cfd8b004ce62c49f74265f06dee24035cb70162663da69dc023d6120c32beed36b7" },
                { "trs", "d6895f5f5da8b5b173b52dd15932f80ce97c2f5ba398cd2553cd0be8d8ae589fb84980c54b1536ffe8fcaf5107a18677f5b041bfc213253a76d4762abdc12c02" },
                { "uk", "38297aace0a3bd788d17b18d912ef7a44a3bc86c88d1845c52f03c705e3e846062f89d1aea11201c300b9bfd0b5503126f981591d0389d611191393113ab9516" },
                { "ur", "068a24784fc8f6fb53f1cfdc506b8209d0a84d0127d383e87b298ddfe408ecd413892649c71f9f07941cea8dc1d1b44190c97d4f37b61aa437747dc84a9070d2" },
                { "uz", "7570e79cda3da4fe8ab4aa4dca8f87b3d1fe02b733ab030a9b18738829504b6c2ed41887a1aed7f090158e9e12e27f78f2d28ac13a113dc715cb6450002aa643" },
                { "vi", "d223bcb679a7800ded3408763fd5c58bca18614aa47a059466099c7a169be49621c4ff5621252682a824989a4bcd9fef1fe105aaaa330f945306ef01777e5597" },
                { "xh", "19c1a1b07123e8201bb8905a6fa22854711f3aba55c854ef948f0f13326bc3df9b328b3dae2ab762c5f316bd5889bcd72c964bc4971411f4aeb10bd0549b49eb" },
                { "zh-CN", "e89603ce110323659202fdddf755211e81560b95be9245d1e0b5d39940dfa9ce1cd938b38374b8a2b0aeb1dcf5d48402559e28bfb624dfd8a2249696d162c674" },
                { "zh-TW", "025cd4773bed81f114a1e289fbe5525c90a40c46c850f938f2d25136a1aef5767192ac5970e923227e7dd1b9a0061b71e43e112320a55d7ba1502d3e96a87fe9" }
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
            const string knownVersion = "152.0.4";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma")
                    );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["firefox", "firefox-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
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
                client = null;
                var reVersion = new Regex("[0-9]{2,3}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
        }


        /// <summary>
        /// Determines whether the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Firefox...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            if (newerVersion == currentInfo.newestVersion)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if ((null == newerChecksums) || (newerChecksums.Length != 2)
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                // failure occurred
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
            return [];
        }


        /// <summary>
        /// language code for the Firefox ESR version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
