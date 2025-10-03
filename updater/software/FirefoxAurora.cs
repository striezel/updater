﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2025  Dirk Stolle

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
using System.Linq;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Firefox Developer Edition (i.e. aurora channel)
    /// </summary>
    public class FirefoxAurora : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxAurora class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox Aurora
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "144.0b9";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxAurora(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = knownChecksums32Bit()[langCode];
            checksum64Bit = knownChecksums64Bit()[langCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/144.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "068d018dc0180ef867a6dea04482f598f941a35ba86b7e37becac3c677be0c34de1afd57cd280525d969d994dbd6819e1b9f4527b147f9126ad7a77a23739793" },
                { "af", "31ea8e8d4ed59f983eb3a32a9999638bdb40ab857e22e2afe0028a32a8c57b70210c0dd45e41cf1bfd83aae108a867421ff94f7f74807a709a2fe0594d0c27a7" },
                { "an", "15aaa56ea8ce946d36e4546b639f11981ea32a4b4015657d40228ee50cf19f798a4580e9cf426ad70a0d84b78b5073806bb15522c4790f16165f616c3bb1d384" },
                { "ar", "4784841a95fe1e33c650b78cba0825e6a84d64951f33c78eb33e0208776a76aa700c6ab48665055929ad0ce1ad3bd9e069a2ae7b76987c0ea69f38305ecb129e" },
                { "ast", "2a3e680e6dc28ac88d36aea8822ef73b502e13ecce30945a78a5fdce3f4b2b07d6e2d16b7c238483eb565538cf09a71187f2b6d94a3b05308d4a48bf8f632cb4" },
                { "az", "302a4c0a6f7227799c0ae23dae64b7c03b3b8f6653a2fcbbe00d399020564bf74282c12a25c94c25bc635c3f4ebd6b02a3a3435d4439fbddb8577633ebe8dec2" },
                { "be", "1ab784b9541052be1bce9428a01a43b9a117718c51f40d2d09c88e0187d7c9053d6a091030e6e36b9af228876b2695784953600821677eefdc41dc636548dcf3" },
                { "bg", "b941e1fd97e849f2141bb84646e104e8ef83ae51627f3ac05c26b980942488f1eb3a17391f4f75ab3a5fbfca444d428ca953b13a9dabb4c4a48f0d7efb4c1234" },
                { "bn", "2c763b38c187fce4eb77d13d7e62ca91e91aa7d1c198587724c2021bd57810ea237f4f02d34bdd8d1f075a254fca62293d501cf63d36d6c1f652b15ca08618e3" },
                { "br", "74fe866d03402c92a339d925d76553fce767ac3c69fbdd4a1144df71baead1089a9f7a6588343817118361282b3c9696e6dfb86a59d15172ae3ebbc25c5e686c" },
                { "bs", "eb40247b5767920f4df96c1a11e69b1e9a25a2c5f9d757dac6a40eb39fa394609076e6ba2e78ffb0c8e0e8e1300b606db0cc9750facafd0fa984581cd2f02315" },
                { "ca", "0e17e34a2252fab54aedb3c1155ddf1079c12f17fea75d2bffa4410473297fa139c610a8c106ce098ac6020d81465b2954fc3bcea5fe09f05fd52aa652067266" },
                { "cak", "dbc7fe26a5ffa6582d570b6765df99153810de8422c5edc228dfd20609a9e6e9a2af2204cd8897fddbdc96246c30d397097f7ac90c3b9f085294e4af3ed18575" },
                { "cs", "2b271e16bdfd374b6231ccd8a807fc41f8990c8a7801551cf82b8c85329dcbfe177996033cc35ddfd82bca42ed3ab574f76f774a49e19e0cbb3cc88eb7ae024c" },
                { "cy", "b4371788e8d136c4f0cbeb4d3d22b463a470eb6cc4adb17f26e18ec91d4c1b1a9a49b6df76a811744ce4dbc83878563a5e4008fdfaa03db92f2735a5d8c91984" },
                { "da", "acf58673f7071962f22563fadb9725acc0d1c7b8998ed37cacf7726671d4b3e72ff1c9290c55d5e83b853c65b28cd4ef35588fe67d5aa37ec01d7598654bba32" },
                { "de", "141fd19236b4f9ea1323c4abfead25e85792616e43e6ff18504ce8eb18074e5bb6c3b3d19a90b9f004c1c88b958afbff268b5dda8ad2f7e32503ca0dcbebe3f9" },
                { "dsb", "62036e30983bb2458b71770578e1bd77be85fae71cb9607375d08837d27dacf5b631736baa3eb961875236720de51dc55822be3e1d929ff6c64d549f3ccba450" },
                { "el", "8ad339a37b03249e8cfd9db7a59379ffc8855b5bd1af0851a5d5e74484605266008dc29533b0d256823ca7591977e5a816d82513664f04c2bf914d0d075eebb9" },
                { "en-CA", "4d416dbc671d6993a3259a287b149b3bdbb9e54f1352ef0c930a33f7c330722cde43278a402a5770c4d0afc19bbef6fcb3ee2829bc9d0232ee8844a07383dffd" },
                { "en-GB", "411f2cd95b90120ee8744c48df332f4e48685b52d6c20a122af24ed0de888c9eb41db55141fa58124fbf2786626af684bddebff65d2c74827f9d34e8c3ac0527" },
                { "en-US", "72a0e365ce01b2dd94b20c5020a33c8e58ab6738a280f7bd9b1019a9f659393ae1b0f2dcd6d087fb68b6e2f3fc52b08f0a09100d8601e603413bf57e15926633" },
                { "eo", "91e5ed1df460a11691e57d9d2bdf818abf3670e9228d81ed1a0e1ed2cad6bf2d920a13d7d521df3c9d0b10c218aa408283b93d63d196f34ee557beb0f21cdf10" },
                { "es-AR", "773cf4627200ef260860fd7fd6dcb723fc6ee42069345fb6082b01b4fd04df8bcbdfc115dd43b393c73ef48ccd40494b6449bb5d767bb5bbe347c9826ffcf8f7" },
                { "es-CL", "af23727aa23d3d453c1061d5ea6170e0a3c01bad74a6671073354c787574ec107307fa83aad9189e8b4c0ea27fb9ed26508960e5282332da0ee1c3a17ec97b93" },
                { "es-ES", "f2ee478532cde49e6efe023bf71c09ddd1d627118ef029285f9fb9f43b94b424de70210bc47507a87eecbb55269ce6f3eafd33754150efecf7dffb32a8621cc7" },
                { "es-MX", "c21f8f7afda2f6344b91f089aae944c66fbd1e643f86a7a41cd3a3c1eae61ed002c076129cd4fe92580a04ad093abe5099f9887f102647f35277060e37ff2402" },
                { "et", "7f2be5fc98f6a69f74926da725519d32aca4fc625e0d8c7b877bf0405d604b8df67ab9956de20f4c00dd8f3f1fbf35d11aed1e1be4aa2e0ff2a533d8a18bf08f" },
                { "eu", "e0fab0b0dc0c23c435d0355197a5b3d0f1dc84ffa589a60eb0ec1f9f6727759f5e8964ffe4335e5affebbf8e7b3902124d0c6434ac16310b8f4ab2034946271b" },
                { "fa", "cabffcc6093ecdbeca1ea1b03f9c49ff0f0816a218b7b85eb322802d0955f4ab4cb7a5d041adae5a3f5cc33321db75ea53757bb64af7a6eeadc1c9b6f2690b7a" },
                { "ff", "3da2e4dd1cb3d4663565526408e8cfc4ee4dadcc22b1644c385aafdf1ee6c4255058be611ff9dcbd93dec4bf8a0e35fc25044716dca225b62c47fa57fec6728f" },
                { "fi", "53f337467c0a5f403c7dd81598e1371703a37803cbf2e81d8443c0341332695775928037e55220892357b219bd6138e5cc99acabc1fb6cad4aa949daf1278075" },
                { "fr", "498414ed382a90045d67db9c8b89998d926cfb8ef024c987e294b0e92faf333e57873e0f406d72aaeb36da419de60652350c30a85014f68e17d0465dd2848fbc" },
                { "fur", "6eb26bff734d93af1e41b33f0e5d1006185c6f3a5d12a734c931daca953206267a813431052ec3f5979229539541055a0b4e3b00251f4f00a0e110fd70cbff82" },
                { "fy-NL", "f2b5686bfc72b85489efc2d3b7b17277f45fd819b50c65c9afb09cd5780874a32f73658f26c1c3d1a06ab5183c6d08daa03e0907fc595d72b88fc5bd128fb94b" },
                { "ga-IE", "2cc726b56b8ecf06a2c6d894a32bbe2f77e4e5fccf0563fbac7a47310f109e07b8235cfe68ca50ceebcc11674a8055ebc2f45a00397dbf11462131323d1da3e3" },
                { "gd", "5a23da9690919f256bba69911f94ba4b7138fc8857df4ec7ae5aae740a9ea882aa7229a69773d69edfa0565603948b5a064a8450ba66ae446a28b9deb0f7a156" },
                { "gl", "b3e090a7ec5067d8a380f104028b5e63d5b70eaf3b31bbfca8dceb02cfb71ddce7be8f4f83c547d36889cecd21714c4fa1e6506988c8eb713322b05a6ef2042a" },
                { "gn", "08a8aa07e70abbab051adaec38c8a590c592b6a283116d08e52ca22159128b91b367250dc150e4f8d01d7fc5c4f2a3536e0bae8815d92c2cc9bfc2dc23b855ec" },
                { "gu-IN", "47c1d2768fafe67283ed550a76c31a6855708094deaced25fe44ae2659e238d61fa35b721a4bec0a3fd1638c81d39dc0d184f54861dd67405af81a9bfb54434e" },
                { "he", "ed5d31b0a5f3c485de44c08aa8b22852220c188d2bf63de754214c8403dee8cead1786fcf4463c66d6aca951ea619544c80589bd358ce636c0cb8536479ae8d6" },
                { "hi-IN", "1b92f10e95510a5c4eaadd336594b9415f31de907592d66379531995977dd81c6212fd47e7b90068bd386d1d4404c05bde144303e5cb7d860d56568b14a9c865" },
                { "hr", "d85a98a3e850d77a34b906b4394e96742b6015121231f7acd8c472053174f42ed01a9fbed8cbe47e9c5f4d4e0b96553cfb86b5ed1e16116fa4d2ba07bc2867b3" },
                { "hsb", "60a91ea53e562983aa6a1f64053dd523a800844ad546f412023b472e5166a7b9e153e7e9a48fcaed1b3303b0cf562a5081f14d2419a45968e91f56b6db9a8085" },
                { "hu", "3a084fe306527bd7b6290464a5bcc78dec56db6963059da2e0db1117961df981ea0f18b25c135da4d115e37ee26d72ca8c6f4b6eb976ffc1a7062c0c71247d4a" },
                { "hy-AM", "c3ae8d6f36256980b44e57337a5dd8a73ce637a241a7b6e334a623cca4ab9e54af6cea573c8aba911bcf26eec7d377548b4b196a0d576f3d44e4fba7afda16c9" },
                { "ia", "9f93ae8d9553354f461acb619949a6099556d9cf221c588b02fd480bc37437b544eb426debb35280ba192ca98c568b9e78c85a372035b881f53c93b1635fea5b" },
                { "id", "e72a3f2dd52bc360ee6aa108c60ae0fff4ad5818a3ecb97209bad50c535be76c1d015d85766f910db53c63b91126b710e7f95b028e90903c86c5050779365a68" },
                { "is", "f43ea6ed46cc79ad4ec7c53e56c95d15d656adc7410eda233887eac4ed7f5e5ed68d445670e80a0be527009aafdc27ffb825fd32da0a01bf275b8caf18304ebc" },
                { "it", "e875588824d8bf46a914402ae33ae31862ec122d324f620ed15c0bcfa96dc20e51dfe02b85651c5a47d4139e62b03111758e4e725ecf6af47d5aad965ecd6f3c" },
                { "ja", "ac0c2e40381f01217b8b889b2456ad7fd86bcf885f32eb1ab9abd786af874b512532fa0b4b00bc938777365a7f784e4ba8934b335ac80b10314e4452ccb472ab" },
                { "ka", "cb49151d46582d6efef79365b3c00f8b509c1539a43c5271cc3d5c8e7b8cebc8904cd085f60e715d1ba05071e64246af6d2794710a79d8e9da4493ca7287cb16" },
                { "kab", "44dbeffdfb1518f6cd251d9838e681c4a1ddd4fe8b64ff51572cd49dcb8e0f7879b6e51d19d9b54a4572d6b1aa5dc9150044d2eb3e72d4bac7737afe8313173a" },
                { "kk", "65d5d5886a095d42aaccaa1ce9aa8f414cc1fb477ec4dd815d75d6f507b4b3ef2296d5d055cedbbff38a1a9c55f6ecff8ffb1f2e66255881907802d2a97ed649" },
                { "km", "fbdf34968b79f163b35ca77cba494787019df2ee44e2c98b5c2d1d5d8b899de32050fe0e7a54b3569e872cf09cd4170c8dedb3f7a45a7c62ea5733ed9b4d44ed" },
                { "kn", "d07ff2c4185f751bd4df366d6db89d7611238d16b65e9d82b824b3b0e071ecebdf07f285a79f9c642b3678524804d75dfccf5db505a9019a11e7907ad80f64dc" },
                { "ko", "db64c941448039ce44608c48753a3ffe6d2e61fa83900880209ccaa4b7de8260274c01feee7524ae12a81c5b91d6ebb57b05100f2d73542784ff4fe181a05287" },
                { "lij", "751ea4f59aaa9eceb32fd339fbcbfc9914a668827b472bf42f56332a12cdeb98a7d9e9bca4a40b9e1e41fba4e3de68c8b283c9dfee9ed7504fe1fb443be0a108" },
                { "lt", "87bb8bc5b1150d9fd2ae84ff4b2701dcfb5e6628592ab0014476fe96e981812b96a1c65f8104b6d6cc8be5ecb69a0c4e9d3141554915bd98d6f40a3af357e287" },
                { "lv", "8bdce5eba7e613dfd0529075728a43fb54b3f4943adf6a5b62eec8402f11c9818622e1da9a6d3cddf6c977aec023a320263cd0fffbb80d38e531f9f952fde716" },
                { "mk", "62cdb118ff5adef21af4a9bca0a3b2ffe014364a7e6b44468d72f89e769f35feaed2c1166f3aa5c09df732b232e73919e3b4730f7c42d3b506014f13a0fe6345" },
                { "mr", "bfed866bbc23034b5175735eca30ee59691aaa472a3bb0a529aff228f6aadf7b4e7c2ca77cf5b471aebfc6f28f33c7da0263938c6951f0ea815511d0e3f26541" },
                { "ms", "f332654f27792d0b2b62556f43b9c7d6098dc3b4bcf9664e2fa66acd4646fe494cd3fbc5f74d942cd9380fbd7c102481c5ddc80528ef8106285055dd23e1995e" },
                { "my", "5f3156932dbcea0f3fea135a7c674fec2f7ee7a24a88b9d8c8edf352efc6edeb07b6793abb63e3205624d29471ec49f648b488391292da567b25e9193a3c9144" },
                { "nb-NO", "70ccc79a6574f37c3018b296f448de7616ae466ee0ff198bdf778d11d0782482f76d703936fea87efd7177e65dc7f11eb6d61d1f94d16daa10e7ea06fbc1e3e3" },
                { "ne-NP", "f3ef0e1a39b4e9418bc787fea1e35c4f7db88105a8525bfdbf07e28502e26720bcb385b1dd602fd9fb03eee4309406594cf6a167b35a0cd631fe722b9815ce4c" },
                { "nl", "e3b8d0ee7b2ee16f05ba90c62ad466ef70eeb5ad148e09e51ba7078b02defbfae74e311d47e6d1cb20d6c2324abd08d5dec7ae2cc6ec18af43773c4f467fd06a" },
                { "nn-NO", "543baffa41d13d9f768031d0032364a94ac47f4f9c77cf24e17232cef8aa2294e104ad276f65223f6e61dc7206ecc794836568923229483d5f7f39f0c52cccfc" },
                { "oc", "70d96949227b32b79ebd7d27cd7fa17bd1c2970bfa7fc46f96e79c0d8db933c4af1df66dfc52fd76a2df76d716733f1d885221ffbaefa49c6086687734ea20f2" },
                { "pa-IN", "8642d9dcb4d399902f2b0777b9c1087a99edc7f9966aeb9c53da3c018ee4652222f058be6082a5c71d517c6564115e01e12bc4d912866f3b9a67799a0a0f9605" },
                { "pl", "efa0f84352cf33bd5ec055ec24ce7f6bc6791d264db8dc8738ff6f6b49c9e8bf6f13ff63d05df6a8566949bbc345ddaecf9e73918c137fb941ade0da0f3f1f56" },
                { "pt-BR", "683b0dc3b90454dd46700e2d694f3cb60480afbffd0502bf8fcebab6e5ef140e43674e796ab9a1ccee976b78fa960696e0c41f25c28fa8794ca1f82d24da2cf1" },
                { "pt-PT", "9b3883244ed89831ba9668b45b2e1e501a9b1c4b5d31eb6405f31faab06e29174387a305a97b3ed53690bff19dd541bad674a6fab8aa1f7396c912c980590bd4" },
                { "rm", "6afa7fc2031f510b66a5a166ad2f99e3667bcd08c6fc3d0478a926b58e914c93271574bea6d1dbe9768f36cf369074096d73fbc9032f773d14bd5c10f2945d3f" },
                { "ro", "5ff819689b4a35f39251735f17e2753e95c1671d2b756054205dc5088d0a9899bff62b7ce6308ca4006f5cdf59dfcd5e785ac4a7c411f139dbbcf3ffbb6adab0" },
                { "ru", "67f67b5747fa61f04afde2ac61a15b8d492639be8d9f51c945f67985312563d85b5c217a7bf492db2660ba1adcf8afb38e0841c1320a6ffdd7626289a8c2333d" },
                { "sat", "63cdc606dccde45f1dc1ef61ae6a7bb484e9d544bc07408adad40b13919086329ba82727498a0d8346bffe99403e903ebc699e8e6f27b15b0ac011bd34ff19e7" },
                { "sc", "f9f6883159406fe69e2d3dc23316776027a550675cc2683b91986f9c90edcb8e61a953a14c16a55d7933c31b4fff1963e0c0df91bd9880af129e4837123114ca" },
                { "sco", "45f64b4196cc435b3cac90354c7e73c141153a034a2a54f6d8fbe58a66ecfeac1e1a65ad42a92f9bdd7a6a7d614d43148af98bab9ca2bbff4ffdb9d57dac42eb" },
                { "si", "2527d5770c18bc6b335940e54b6b88a33c800a17ee61068069b43d4581de606568aa7cac613da88d253bb86f1c2bc8d84afc0191f5b28541810bd4f46fd44180" },
                { "sk", "64e81644247398c4244a4bb9a82a9f3656238b8abd60dde10825b26f7760978d5e16bd0bb92c49ce3e89e8b7f2f3bfdb7c4b0ad45fb2bd8aa81f4e9ae98c953f" },
                { "skr", "5343bff8ad7b61c2b3ebc217808b6c6a60c7372e75d62203fff2525afbf552ae74b2fbb59631bd7c1d7e7381152588acb686a4c9ec85287327bbff4aaac8aba7" },
                { "sl", "ba34187e8df1baf311b9ccea9ebe199adf4dfea300c04470cef52b477f5c37e195083a89db00b912f69b77b34ad6123ee52d8158a75c7dfa91ca4ba3180310f0" },
                { "son", "b8c58fc3b3bb9d73afc14a9ba236d7ace38a72eaf31515be5f826c3ee19010bb12ac97cc031c584b36ec052b84a9b8f44c2ebaee99ff2319c7f3ce11281d2a28" },
                { "sq", "e43428699aefaf92aa73b30ed7f7767356bbc526902c418a89ca918e09aa361e147ac13a5736ef0f57e949f229ebf65f93da4d6405013c789fdf4db20841b516" },
                { "sr", "702147bafc5f6b186371e3718f099cb13cd9729d8c7e8a07bcdb5d1e1d378a9539589ee0d9206eb722893088d61b777e3d74ca9d0921d4c20d70eac2542c15fc" },
                { "sv-SE", "971a2e6c769a6572dc7edae4de3af0bb84374da90d2f0a14bc50823313abca09112e07bb98986acae1be03a9ba4c7a39436123102d15e00f82a33af856614e4f" },
                { "szl", "586c7a0422c7b57dd77e37017159a7acac12a0c9860f7120089f6e0dc97c806c1241ff06383ca20db0c81c791c8f266c11c378b8ff3a2bde6c89c5e153bed800" },
                { "ta", "bf72e806a19dd1fca79b4d09be470debc2613ca7fcdefe6a4a1236e2b815b6cce7526b2de3142f90baae348399431ffdabbd49eee3d43342c364fd718535e4d7" },
                { "te", "4504b90ae8c9744119ebe37b6e1cd3c3f85dcb6c2d5314f90ae4f54a370f8791bcc00370fed187cd2c3d06698e26aa676826d578aedeb84c02868b277474f42a" },
                { "tg", "58eef54635db63a27b5da2135a8d93870ff62670d3af9df5474b6aed363cbb80cbcf4955d8ee2d829d6c75b071272d7149c97b3b01b25f5f73c7ab2afc125ed3" },
                { "th", "bdeeea9e9baa59da10e3999ead9dbcd890189401d45121f47149f4c52ac30a16f953c1f37dda1acc16763830c76c4f5de55fc0faa086f0d17bc2952be72c85b3" },
                { "tl", "77fe0daf724c26524207624c797d187d08b766f8d1f470cf7d68fc9df8812a2d4e062adb44cc51916b516deb93d5b7cb6a06614112e3ca4b0fe59b992a115f8f" },
                { "tr", "c943e0d1800327fba01b1dfa404bfaf56a61c771c3ab155795f402b2171e8fd4b4645b0a612826ec269629a12e1e134202b1fb54f13d1d1803ca664cd64dfe03" },
                { "trs", "a0b3acdf1cc9cacbf89448831cb0e833fe5b2ff1f5a6f0526396c7fa88193f07f47d3b1dbabbef0d348ffc0b522490efc5ff53efff84e84eb9465c300e64518b" },
                { "uk", "37d7eb78ee0ecf4af0e22eaa70f0a7712e6735e2816af9931b04b17b10759fb392db05b964b8e3a66b26b278964708b65ec987a6807526219d780cb0c1b47799" },
                { "ur", "a74c2183eb5bc455e8867123520348356a64bb9ec099b3fbe77781a417bf1ce2b580436b62258e616b8bc9225dfb71e52e6bbfbbe0df82c19ce814dcfd9fff7e" },
                { "uz", "9dc8372b11f3b1a0e5b1a7668082c8d661c060cbf3f6aeb8291313c057839946a03030f4357e967356f132c531084d516b2c4eb15d1d30ec594ef457ecd183c6" },
                { "vi", "48ab417462d126ee121a0bb408d77f8ec1eac122a9be18ac8df64a79a62f06972235320302b520f3cb8a57ed42c0b0eda57fd51cad35ed854c1abebbb55e6d93" },
                { "xh", "8dc011b11f36121a8f6d8fe57364286df543dee10467b7cf03c6eeca984f70b78183e84ae38e40520831ee2ffd7d96d1906a8c674d748f90cec4bef1660893ed" },
                { "zh-CN", "3e840e92862aa9b773717bf0ca90d702ee929213180eec08c8d723b45c56495e644dd16cbc72048645ff6ac9b7ac01d62fa8d4636b862b26eaf437a7524e6694" },
                { "zh-TW", "f0defa83935bb948330e7fecac461ddb18aa53eb68814d5042ed167f93026471a5175be843f33ad7a3107af80fb0d612c4343344e6049e5c1d6c18f48c7530f9" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/144.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "7e58c98af938a327b3be355d102420dcbd54e94550213156cd6f4ff6768780fae3e65bc56d9ba0d602ac1e2a95e9c59a6ac6e64600a5c0bdc31cecfb3e4d13b3" },
                { "af", "fe766cec26a47acc190b4b0cb68e570ee5ba0c4c7eecbd60e8048d567d5fbf4e37d872eb3b69d84539ac2716ede62dcabc4adcd78935b1290bb45c5080c7a8d9" },
                { "an", "a2988358d64f72d0126c7b495fd97bb31863c0a9bd564fb859e0703227ba4cc139ebf0d878743ec0c84e677a1e6c862a40864341c26bbbce20ae10303dfe1c66" },
                { "ar", "a6be8e6ba4b0d9281a56c7a977d7f792f9f622bbc0e7eef771f87d60ab75a64ab449dfe7d78c6c8e94f0ad0eeeed60d7bccd523eea37bafaef505c3da5e2065c" },
                { "ast", "d5b00bdea1917a4e13c8a876f07ca56c141fb0777e07bfd31e8044d76a87051be5236fa1c4e67f381ae512518fe2078451058e31813e88d46a60af61bcb937b3" },
                { "az", "d1d8751669e3303bd8b37a98054cd4fb8469c306ce8218f0c75986d4ad51d3429192a24754ea913d0543552a29145004075f477bb14f300769ea35969ac16b52" },
                { "be", "dbef1386c53e547d2bf8ac3073776289ae55559c9e38517b9a72aad106099547933a46ca1b1b51cde6172384c800cb7b0d49edf2666a6d7ce0908ae681719bec" },
                { "bg", "7c53774281be502a9c1466adb86b598ec1382d61e948ae507ec3afa8f23e2783b3db6d27694b0d43b477c5703608162ab9f34109d0119a8dbcc6c63c7868062c" },
                { "bn", "64ba625fd96e9a7db4688f0481b89735e2ece4389edca592678c1c50b9306c014d6cad02301dc66823b2d5a5d9abe16d887535d4c71d9ca4b647a91e9e389fe7" },
                { "br", "4708df80311eb51ab23d1d4c7f72e6409d65c7716cccff9b49b737ddaa069cbd9debe761b900ef68fddcbf661393050c11effb0bee83fb460be9db795052b2c9" },
                { "bs", "3aa02ecf2abd9209033784e62a42e3ef1d016652d8bdd0745cbdc5bff92b5fde3025f10598fbd9a8c60222d8d978400e452d21d8ea95b35886aa694d12c91e0a" },
                { "ca", "e3a485e484b23991c29c082213ff8d75ad0a0fb669db791f40ad782c7afb8d9601d333df968f413b212454814747c694d70dbd2049aad48e4b8b89651c708faf" },
                { "cak", "aeda7acaccb81d35a276ed96893553766d7bd0e769f224fba8dfcd9fef7537dfe6aab509159e0006279dc94b224eeb31bdcfb934de645274909851a48b80552d" },
                { "cs", "a3deddddadc17ad5ce3283c3cb41f63d064ec1977f62f9f12ee6e2d4dd127e18bd678224d2ef283f59c4812f476cb1635f627ee2afac7ae7bd49bfc8a12d9440" },
                { "cy", "352841fcd7ef22c62c2e6d125ebaa0887babd84642e381c2db33a91928cd852ed46826b8d4f3ffcff3f15de50ade691c1b5eb0ca15dd939964b5a99b521d4d1d" },
                { "da", "364b0a11e68bca4711b9f0e6039fe7a26ab30635a58985808678db08cbf6b8d22e374756db8e24632d7e99bb314abbc79b23cde08d54bbb1be68849c829667b4" },
                { "de", "8001c695bab8022bca30939ca123a3532a3d5bf6607e0b138a82856c60b34220d8f547917fc7a267e4945bbefda0566f80c5e57199d650710aa8ac26e796f065" },
                { "dsb", "e65c2afe89d1d70051365b33547af75971821f361b466fcc936f3cc11e87dc713abbf75d8b5296955db4a77e634f76794cf741cd858f0a9258bdc1ea1b7b5ad3" },
                { "el", "e99f975226b66c67a548aeb4147ff6feee6bf00c025506a23d91c2e91efc4b8acb759429d8fd0e86065b830cb8d2d67888c85bcef407396169ef3b0e86685529" },
                { "en-CA", "cdbfb5f0beed0b7df704b7e6bba796a3a21e25996f9be13f56ba657c53d92f155e19c3fc79573d8afa6fedf1d88d9ff2fac1f14442e5781c097ba2efb045d143" },
                { "en-GB", "83f2cd51a3fdb9c7d48b972cc3d51df0c2c9df9747a44a89cde9ceb725429d389b99c0de45c6697306c7201ffced87c55be7a6812528988744fa3c71c312b748" },
                { "en-US", "ca556558257bc330eddc74feb72d9c28cc4e5c29fc38365a08e9d3b88b673075967ec7e29dec81f9bb96bda5d6784e6824bf25c19dcff77f47b6721c3d6c4ee1" },
                { "eo", "b25e60b744f2bdab639f841d596ba3c1b63edd901385f4c1bdaeb2c0a6973e2e4e879d10142d71818e700b41d083c25f09568a034bc8044ecce78c36183577a9" },
                { "es-AR", "386f7a49ef393963a3a6f51267cb52586c7eb66f1e49f18eed9265f5f5f070e0c5751db088938054be5bf06fd5132f10539431c9c060f9049cef77a42ee257bf" },
                { "es-CL", "751bf4988894f903b4bcebaf4e9dacb2a386ad483df114d8881ea280dafa611974c12f2f221ab0ab3534fcc5c657c65aa896fe0bfb72dac6923f8d88e5ec7db2" },
                { "es-ES", "0c6b937ee7848aca444bb15a3a2837f19b5d4a35776200320eca22b71a1e2e7c237d309941dc83210e8dbd762155ce3d4b30dce7caa2c977e7cd4dc68cdafbdd" },
                { "es-MX", "c9b7defe4690eb1aad35bc5bd442011ae4da4d6cd34561ec99c34a76293eed451bbea0e095a0dfbbdded30dada1592ee3f67eecf82a4824af1d64af3478fdf87" },
                { "et", "3105331d8d3365eb07eaf38fce6dd42d2b9bb425d56d65c23f57ae4c9a22bfbdb089097f6c9d0b34286fbe60c545bc027f61e250ad69d0b52d623d4299de41ea" },
                { "eu", "3ea8012fe7edfff459e4e082a925edbf4e518db830d206fda44fa1a3716aecf3dd3a66b688a11317f11d18fdda07ddb28fbd560d7ee833716905e534ea053784" },
                { "fa", "e0fcd902e048b049f2bf6962d06e76b8dcc87efb62d514cb46744726baef6e65e4e259eaca7f23356ec394ca3a5cfeb027c8218c69a41db2979a33b373de6142" },
                { "ff", "2f7866c590d22482b90add531632c5d7a747c617c501164aae7a2fa4684491837f364788d0eeda2da32fddc6ce414b46c0d14dfbb7ac106cc7b2817ff166ccb5" },
                { "fi", "3a9f7168463246e39b77db47866a1121d1144dc7af0993398c4547e6b6858008581f800e1ef7dd3970747d4517ef0453c6b6ab8124261919c8816b04ebd2ce47" },
                { "fr", "c5bba6a543ea5ce5f46df3f78fd74dc926e57aad467e68ff09b0381e1f73214f84093d873f3e25516ffba41e8950cd406fe71387d657f3801c143492403bb250" },
                { "fur", "f72516e49d6abbf5644047fa9f8f457a577d3c3b7a8986f4cc971f34b3bc239caca7d35b88f35f3cf73815edf70eff3cb0ad33565d8d12b053e9727a28c39e69" },
                { "fy-NL", "a80257e1b2004f805a727560abec09d46f66a2191cb37db0c04e14338436e4779c6c1f8dcad7267f02bb568061172a5ce86370311d2f04f85a461ef845ff8057" },
                { "ga-IE", "96b253278f44abdb6034692688423fe935417f8179c69782e504e814a66147f0c922cdef716ec6b0354ee4dad73a3f3873577235db318fe7281b292ff4a3aea4" },
                { "gd", "d2550d894b584afd9685a61ca57cf18197539a6cca7cecb005e3cb948c2d6f95090c07d06231f75db3afa28d02ba96455b1a16a86f30a4f06329f29615bd374c" },
                { "gl", "f2aff5e04e873053701051aaf307cdb3850838876f88af1134649993b26652440f382eba2f435292da1dd32590e10d6e668752dbd4f28516cbc47acfafd91fdf" },
                { "gn", "1c9a53190429cd3314c2fc9101078eeefd977d841d97ad76d554e95d457b42883858f2a0880063b36d43c72828836a9bce09f38a35f24c4052fa64e66484fb1b" },
                { "gu-IN", "0e8b8b737f6ebb1ae531dea5e08f5febef09a3bc6baaff6159f29950cdd2a634d17ba2a2e4917e0508137244db092a17027708b9184f646cb2b12e43c8345ff6" },
                { "he", "1acea915640943d9160d9c0e2a322eeca1accae0ebcd0aea33a66e35260a1782189e99931ea74e9fac23ef16fb1f7bc3be290a576d34bac1a87132117e001f3a" },
                { "hi-IN", "64d8c2d775dac17a2e31b8fee8d6b456636d922068c782ec28b5d84f6c5c9b2b3160981357eae195d5135945dbd557ca13712541a48521cf4e9f44075990c4cc" },
                { "hr", "ce1d8790a26b2c80101375b283bde58a60ea9be4b2b2e990b5cdbcc33b83ac8ca631e5b4343a3f7ef0adc3cb7270a438818a3cf015ebc90af03d717a6ecf9fde" },
                { "hsb", "4d84ac9e3c5a5b3a1b3ef16a7a9dcf2d6fbaed7e5b236f63d3bf4dfae5b799fbe1de7103b632e5b773d002ab2f144c5ae967fb45f70258e84b7f744eb360f9a9" },
                { "hu", "883b543a5a07c45fd38165e47ce387b297d15ee65ea94b7c556253eceb4781b67de3cd6e34b2e89b6a4cf6fedc65b44ecf98fb76b6e60db8527e03cde551813d" },
                { "hy-AM", "f73b31842bd6f84175b5c8744e55c0cfd0be58356fc0aba654e4606810a6a5774621e9d9d75e492b4fc2dae965d62d5f2216f9d979ad7a8cb1ebde419ac1df75" },
                { "ia", "9257e0d4b2edd20cfdef50b56823d321c082e04f165846a5818fc788d7f804d7c067cddebc9bb9af6f040d8fecee2d643372de39b17ba537c3300d1914174932" },
                { "id", "97bdf272c98a178cf378e17b7d91bb31023c0eb38f446b11ffded8db20f62003d9b6de54fc2a0bd2dbaf5b3c486f19e7cbfbcc86f886aded05b14c329befa07f" },
                { "is", "5069eae48775e31cce396212bb776c5701a799d3972e98c67efb664648e9476ce4cc11ba385216e70b35bc3a3e9cd24d37037409de9f88b7d7e816ae2a14cb17" },
                { "it", "8e584cc5048a4101309facf4409ada47387b245ac6ceac8b8b681873a258b925e8957830c643798d4978704b688376e96f7946b46ba7912edbbe235e21bce1f0" },
                { "ja", "41e98298f94e17567f6212f95819f50f7d610f689a6922c26b2e034fd944e77d46078942964d4d351074abe703f956886db4ddc6f8b7e71a2fe3baaa830d8987" },
                { "ka", "715aa9036c9cdfa0c5a26aeecad456fc227220000639c9d6bad7f3e0a0d71299da4d4f202655abe4ba497c7fa15f94a37c372e1955c865a9d91908d297e577ba" },
                { "kab", "01ddc9cd0172f4c83389cb212f1918fa9114dd43f89e61ac59e7a0ca10c9d885e00086dca5bd2eb76d728cf5e506d556b614dab40b81b14ac811dbc8870065ac" },
                { "kk", "fe0c3bbd5c51cce759d20f51739ecc2f718b77a8c01fbcab2183a5cb792da7a452e8ef510ff89bce4f5e83ad7a23a786408065e1bf82827ed992ff30fff50b13" },
                { "km", "9182b3b959f2fefed452ebac39f2e2ef9414df3d26620b8e53341dcaeae7aa72f59c6362687c028fa3afd621533bda1ed760e8dac4e36d36d8242dc4c7e388bd" },
                { "kn", "208bb0d838d32fb8c449fc4b7fac0b7ba46b550adc821c53c1576f3b488c6b1768129f94f4d41926c38463d72ff29cd135e186b237151f9de6d5772c49350dc1" },
                { "ko", "d33eead50661452d90dc992fdbaf2dc0a757b45e2307edb76ad630947718706269d43870046ecea45db16587d81f0d635b860d5034234cd4bb21c3ebb6a1c5a7" },
                { "lij", "2b09897a97d766cbb60b7c27e6d76901904c16b04d494a142d76b49888539b106f670889b75df2372d3e7ddf50ecf56925bdd13a5e5f9ce8902b284155606114" },
                { "lt", "b71b24c0518bd882cfebb6a915991276ca73314548e8fd95ddd288a65671b54c3958d4f72458a5acba1f557d2a8888d8973e0d3ef49007badba6436235808b60" },
                { "lv", "adee7919a6ab9654df2665c8788f753571b643027c67ab938cd1c5e5ff785a9700d193ef541c9a1011cffbc76235b654b6d68c911b957c9ff446d5652afc54ef" },
                { "mk", "84ba63e6ce063703d3b2e823511b42c0089db8b60a5bf7b6f1ad2afae586a1e4ede5c1ea1a5cec77a9af5ab53fb4de0df965dda787871cbc149a9d2459f54961" },
                { "mr", "cbaa91524a7503aafd1b62f65a62a7a603261bf3573ed583fb59c7a89f007993f83f6e7814f55a38544f67d2ea6376504e42d57075c88e2c4d34e0188c33f431" },
                { "ms", "e87995cf4d1c55e744c9dee3553245847024bcc402b4b7cced11dd9e32cc75e264bad6a8037fd6f9c96753b03abc318d71919b9add7a126c4342a0572fc8481e" },
                { "my", "ec24ae245dd3b6b8a0fdd96e74c817490886de41daa524dab196b6a01483a4aa36efc0a4e6cacbd050c408a850c42bb5cf4602bb57536454b904e4333624d592" },
                { "nb-NO", "0030dda1a9f57a72fbaffa791f10f9a31991e6ab4579a52bd586d1da77aced559f9f4e602f11721d6c176491571a322beda649e0db1b016afee94360baeee318" },
                { "ne-NP", "e0c31c7adad6b1ab4405d9a7e65c584c361c8ef3fcb285b8c725faa7e5e489ca16eec80b331a35b1a936e8a1d583a868fb7599d83c13645f94dfac68bf68f58c" },
                { "nl", "de0505e3c28c21b2480e4e9f054e35e5a6015d7f14fdbb1f253c052b7f4e3501ea1d075a605c0148bca9e693986f64410116f81bdacf3f7d59c1bc922c3c27b0" },
                { "nn-NO", "f52f672f4a24f302b7a6c635e75fa0c97ec3f2f6220cc6a9230bb7ac2ffed08047418fb3d0a36e5942dcbe3c29293a289965dc929a61b437324c85750f717532" },
                { "oc", "9bc7ceecbd44d14a72753f34ac9242dbe8120af9b7250f1505ad71deac6232a5d1babda11b31ce0eb4fec393d11fe8cfb4bdac28a57f3bee79fe796234deae48" },
                { "pa-IN", "8c2c3e8cbd5b9bd24e8beb5880457fbaa9bdb454c916efb21823663ec2b43fa68702a71f613c8311cb6a1b23565fb8c9fd070758430d708a6626d965ac053a44" },
                { "pl", "68cd0e8244e8aaf8f4894a78f054e126594951c752b2a4633b2343deb5db82e34b65b13f7f26167668d08d1c7b0773c6bd61f856abf60af181c097ed54f05f44" },
                { "pt-BR", "b8cf3f1d661ac7b210e2d402740a23d76993f05786645b55bfe1602b1685de307d6528ea71e1c9c7d020c53ecad340a1786272fe8b497189f3f02a8bdcf63851" },
                { "pt-PT", "cf5bd21281630fd03f8d91cd711a9f59fbe3f3b78012547b761e59f15b5f98a209770945c7da1efcd43db934482b0ed1b1a97d9fea50dcd63f35408e79b8edce" },
                { "rm", "23b0c75968e3245c12634ba433f255d53af51aeb69b126b3dde890c424fb981b6687845f40d89b37ae64b4205e2658765b8d93ef885be7630a601cc5db4f0921" },
                { "ro", "9c73b12b0e2a5e51e4a9980a13ea387f419898bce4bb0e70f890effecde0dc732b81df4c645affcbcc67a5a743268425289c752c47bb195bad041fc6bc29fbb0" },
                { "ru", "915e86928ccc31fc825a4a5cb14ef8fda772d7804111a5ad0c7a0393fff15513711718e7810757df2c5ee2265dc32fe31eb9049426b21d2e1b8b6d55709c294f" },
                { "sat", "fbcf84c0ed8194f58cbd68b63d7e70f218e5dd3e22c3bde097107849f9c48a3014252fcbca0fcbed477feaca056c3d3f106e994ac2a3a73b97dac3d52766bb1d" },
                { "sc", "fac0d18f3e5bc8c702087c81f14a20f61bbed98f900c4575e6e783018520811d6742e8eced08af195e828ad107222aaa08d4d1cad9876aef44947c77b6d886fb" },
                { "sco", "eed69e603966a50c076ad2a142346c6a00ceb792e4f9b21d4b372eb9d111090fbbd62a53e923710a32985c01b7abd12a4039630642e529e79f95b3a4fa135f9e" },
                { "si", "95a7fed950521c80f7db450bdc15ec7defbd08ed66aa745a42b82d5fe19296fdd39b69b6689a23c98030b8c2d91880d223139e152ec8300e2b00070bd93e2044" },
                { "sk", "b8baad6cca405e2917c33da1c104ce95c3d2dec804763e3b0f963d93a6561fe3f68996c1bf0bcd1c7d81e2d99cbd8fcddc386d2773245f68c4196ede11a46c5a" },
                { "skr", "b802930c0c142034e58873ac1fc522ca72b27b0ea996dc7ceacc00930a683bd2dfb96c49f5c67d083b3c48a6cdf9750f26ec0f339cf1b5807af5dc585d4e7ad3" },
                { "sl", "d40b260c5bd9df4bb159a069a511d42a3da3b640819c85df141d8f6c471199a652c24544a395ddb5ca75b525e4a8076903138e9a25e3f47ce6e23866fc6c869c" },
                { "son", "83dacbdd6c9e99b516342503517a3a01c1ac682bc3da13fe4de525a459da158c5b34d22b7bfab01d5c7e2ee91e8e58d81d90e45fb47d0a42ecb37d47cb3d478b" },
                { "sq", "ff9ec9c687728fc9266c331f736b843877756c0b1b9db43729d8fa3c5e1a4924b728dccdddb1418e5c6ac08659b135135ccb8c30089ffce6ce4b39b75be71fbf" },
                { "sr", "3734d00c10e4761d4266eb8b8e56382f1f67b91f80b7cb33749561189b1650276ba15da95412aee0ddb3c32a47f71bc27837b212f062e3777385845fcc6ba653" },
                { "sv-SE", "b765d41227b8c4ed64f2390a6029d3461fe41ee8639ef28e5ef2e73187c10829c3cacbff95b373cba1fd5a03d13be856a5c3bc16c11fe952f8cb3da22c631c17" },
                { "szl", "67e385dd6a1895f1301473741b31548c32768ad464102a1d98cf7b925c6a488883e8cd3d9ce9491df6aad4b4fc82c6c26d7b16b1253d2e5e6c6f362fc45db107" },
                { "ta", "6976d04fdeb69d66d2334259f1f331572447e76e40f2074178b9238cbe1606ae477aecd4347f63902a078de8af8a969432b54c43c387fb471c18091e388a3e51" },
                { "te", "332b4cc17749b01a58c3a6be9601eff974f9c6794d6c5d2af4aec548defd1cfa738fe5e19d7d4bed57c25eb752e9d2b874ee82aa47dd0853daaa599321d787cb" },
                { "tg", "8fa415925a827f8105c21570aa7706c2015341950b40b79128ba8b1f8dfc35d3881fc4610ad82fdde840dfa517929bb8c1f7eb908d11bd5c72a8cdb538d51f3e" },
                { "th", "ecb53373e4bc9412978559468bb0a62fe069cbe3e323dda5cc72993b84dfb4f9503df6ea9ccf5fd2c2ed419c78091840303c37562d08ed49bd163d2da618d4b3" },
                { "tl", "7817aa22860e163216bcc5eb7bbfe999d04d376a92d4c956cf46962db60ee421997200de081d83f53094ccbb47def3dbd85540585db1ec50ec534f712eb1540f" },
                { "tr", "6faba777f3fdb241336702e73773ae9c36699d28e28db96e0a9308d323e010b720ab68aa600b0e4c95d6cb0029f1cef96430fd4d409f7ddf31c40b2a472da522" },
                { "trs", "7f20d15f9e72e95a42d8cc352667494a3e9d3cfd291df4240c63427b0bf08077d43ea2c1defc0e5bdf08ab6efc12831971069174fa9171295a134eccc9901058" },
                { "uk", "cf54898d7370c6b2b00c08219b1635742da4abc94ff11286871b22ac250a44a1d8b8221797d7592e8921e1100cde554daf6913147003074530999929317d7718" },
                { "ur", "75d2fd1db82d71a4facfa6f38c396fc9ba5000a3c22f44dac79de9e1fc6cf4a5edbf4503789552dede00dae5fd8af3b8b86a35728f6841bfdf4de804d01ed6fe" },
                { "uz", "073c0e261a87912b8a9f2af8763d7c513bfba7babd52f572fc4ac674e65681f5192ec24e7fcdd611b38cb351fc650d1d134fb58190e16726daefe32895682f62" },
                { "vi", "ffa11ffcc44c1ef293c66e35164f931b8c50a6289b46858fadab37d6f3097fecdcb12de943169d82207317f23a44bba34e97f181ae180f4f06a9ee6c6a6e3cd6" },
                { "xh", "3f45ba397d1a408409f187f6e68755824563cc1b59c10234853b7df80d2b4d8792005f229208420ea372d451b028199cf9b816fa32703e4c6f0fa939211476a2" },
                { "zh-CN", "3eb41d99daebe8b46429daa9ca3c5e727c810c2aa1bdec1f20fc844c45479f02d422cabb8831b923538c5308b50a0f03c21e4ebe738066203c3e992bf046ad73" },
                { "zh-TW", "ac71b8797c5bda110eedc5f69c072c0dc46763143c1f90d26ca107850c80cf900ccc9b6ce64271c023a016bab81e0f69b3c6619c0afdadf47c61c51c5a2c4b55" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            return knownChecksums32Bit().Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
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
            return ["firefox-aurora", "firefox-aurora-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox Developer Edition.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public static string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                htmlContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                return null;
            }

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            var versions = new List<QuartetAurora>();
            var regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
            MatchCollection matches = regEx.Matches(htmlContent);
            foreach (Match match in matches)
            {
                if (match.Success)
                {
                    versions.Add(new QuartetAurora(match.Groups[1].Value));
                }
            } // foreach
            versions.Sort();
            if (versions.Count > 0)
            {
                return versions[^1].full();
            }
            else
                return null;
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
             * https://ftp.mozilla.org/pub/devedition/releases/60.0b9/SHA512SUMS
             * Common lines look like
             * "7d2caf5e18....2aa76f2  win64/en-GB/Firefox Setup 60.0b9.exe"
             */

            logger.Debug("Determining newest checksums of Firefox Developer Edition (" + languageCode + ")...");
            string sha512SumsContent;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                var client = HttpClientProvider.Provide();
                try
                {
                    var task = client.GetStringAsync(url);
                    task.Wait();
                    sha512SumsContent = task.Result;
                    if (newerVersion == currentVersion)
                    {
                        checksumsText = sha512SumsContent;
                    }
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer"
                        + " version of Firefox Developer Edition (" + languageCode + "): " + ex.Message);
                    return null;
                }
            } // else
            if (newerVersion == currentVersion)
            {
                if (cs64 == null || cs32 == null)
                {
                    fillChecksumDictionaries();
                }
                if (cs64 != null && cs32 != null
                    && cs32.TryGetValue(languageCode, out string hash32)
                    && cs64.TryGetValue(languageCode, out string hash64))
                {
                    return [hash32, hash64];
                }
            }
            var sums = new List<string>(2);
            foreach (var bits in new string[] { "32", "64" })
            {
                // look for line with the correct data
                var reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value[..128]);
            } // foreach
            // return list as array
            return [.. sums];
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private static void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32-bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = [];
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64-bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = [];
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value[..128]);
                    }
                }
            }
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
            logger.Info("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
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
                // fallback to known information
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
        /// language code for the Firefox Developer Edition version
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


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32-bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64-bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
