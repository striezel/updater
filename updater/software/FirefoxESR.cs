/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018  Dirk Stolle

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
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Firefox Extended Support Release
    /// </summary>
    public class FirefoxESR : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxESR class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/60.4.0esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "2b9d6f2412c215f34ded12f55c9e1c4f6a9c8771f806a768da33f067a8bde384242f72eede8bf63e6905cff28885e693523c7e50bc5c6473545f238dac7a5823");
            result.Add("af", "19040e03dcad479583fb5fe5249a1105a28e610cf17c6d40f7ae4fdd8fc56a146f09baa4cce963dfd83e8391553668d92da1c2a78f183fa94f6919aca31669f8");
            result.Add("an", "c786eb360745f4eedb22f299717ba85e6f0dba4a7f9cdb19c59143ecfe09ded1d0ca7b88af5e9b2c25e4cc3bb1460b6fbc4348aa076bbe358f3d2e9b88709de2");
            result.Add("ar", "f4eba9188f1c9ab73afe3ff55a5a27cd614a6ebff5125b6467440336c42028cc47b458a2811dabc324f749ee124f616dbb5ca549bdb8bc7a9797b60643dc508b");
            result.Add("as", "97369f1cdccbe0211f213b5c9f009435569629ee46977ec79a4a1f0d8d8ee4cc44c6392c5a3f12d0ff23965f7ffb46099513de8a27e4d99535639a40ca1f6119");
            result.Add("ast", "3d64c25df1b03796c0686c102d54d79848cb8578e9f092b358e4bb037f0f14c93821536e5fa01d6268e25c47a4e66f7d6cc5053fb083a79075172c8c9cb4fdad");
            result.Add("az", "992cb535e0843b9fe22c7b4ea4c4d73a08414178ff6b46f96187039b1d72569818bf6802d173182994669b9d71e34deeb06f34d416e0bac52788256a57b85a5b");
            result.Add("be", "89d2a9f92db8187d008fb9ad67a97e7642ece7132a5c6faed9f4b1175cb369802f5338ea4c294d31ab544cc99418b2b06353bba92a28bf301092e62173a2c81a");
            result.Add("bg", "eb0c1973533243a3d78460d1d43376dc6342b05a854a81221d59bd10c0fdab63d5b28ddfb11460d2ac2d48a21a374482af96a3869e42bde263ca186c8c279712");
            result.Add("bn-BD", "6fa843e84ec9a3869939d83d2eaa1c47ac21c49f2ab6ddf578891de33e53ea676357601f224a27a931171de4d2278c817fb92c91eea12dad72ece9cc9403b5ad");
            result.Add("bn-IN", "5907568c7ede3e58639f12d8c238bc7ae81d4d7660e4876119f0a83eb117a755c6e1ddc55cc10d7282aef56d0b984707f11eb93d2571d536355172fb8c6063e7");
            result.Add("br", "6e38e34641d2f41f87e0dc4b17a8f76522411f69348ceb3c5c7007cb851659b339c3d48ab5fab5ae15f723d92b68eb1f821281f0199fc6e83b6d6bc0a38a2cb6");
            result.Add("bs", "73284c4ed2ec8f5b6ffda30c08ccdeb1e8f2ac03da7f68edb26a5f55b4d67ff8c4ebbe0cb94e315cf559bdd4cebe3240cbde44b64a8a835765eb0f4c8cbccf45");
            result.Add("ca", "67b382146106654e950835edc60e80a6a5d8c577335d9255a8012fcf6614957c14b120c63f9a468677968c238253d6e8471bc4be1c702cf4bf8ad4fb140ba551");
            result.Add("cak", "a76f596c626b1a53313072b8a478fd3f3164f6084fc7e8313ec48850a2f3cf34c03fce54ed60d6426567d92bd88e3de6689c13126d7286c6910db340e74a1420");
            result.Add("cs", "056b9a4104b2ceb22e859354a6be51081a29122ac298d32fafbba29b1eb7dce44f495276dae25e4afbfdffd65678946cc585338f32ae4d2dab51acc73d2bb36f");
            result.Add("cy", "616b724e352c75a887c4415e71455df8d5ec01537d01159d0fcb34f2f47d0ad3e4b24767e5591434d06c3a29634de00b587cc692f2caead68d7ea4782899e9e9");
            result.Add("da", "ef89680304219683cbbe9714e171f931c9f9e49afa85cda4aa5d3d265840dfd5cc1acfbccf0d2c3c14deb7eb5c50c154493ac18ba663bc9e070ba8b130f179ce");
            result.Add("de", "ffca6d034d44f4d932b88d27332e122e4327e1270c8ee2f61f9c36fd0571b98d8973dd32b0d550d4404e3966511fba972571cfc70609b39aba6cdf34231ec798");
            result.Add("dsb", "28654fe19838c2cd0e60c838f187ff81698c3922d758b2de40fc8158e63a4e2c226fb7ab553cbc01435cb8f2c45f617458b41f6a05d1f476436c50484a2acb66");
            result.Add("el", "efabea38a6af679774555092095589b7fa59b2f69cac7ea52a17944c35db765035ecb190851bfce4a93442591e440486358cbdafa6380a652177079e1ea6407b");
            result.Add("en-GB", "80fac4c1cf15878c83cbc732533eafd5f25b1b68a824cd10d839f2b4e69119e1c65b7349889e8dd436c039fbd15c3413729ca996a37e85a92c9e3c65f136394a");
            result.Add("en-US", "8710f72626346c776eea7f13624e69c2a50d59b4342ffadfbc6ec7730324dee745f101670d9dbb46e2bc73f03165ce2c5efd6175c0df7e9daac32e68eb4aaa6c");
            result.Add("en-ZA", "123de81b35184bbfd3341a7917ac58ef4e4a90997739babf5b792545fea70ac85eba5211182a720f4c2cc4a1a2625832c7342397037b2108b354bcda523817de");
            result.Add("eo", "ff32cb7e1cb820c4b0e5bf53f965a3be0301021b2bb4424dbef9fe0b53fdb5cd143fff2917af42d8e6eddae0ae3b6f88a585796fd658fc264deb584c67980f86");
            result.Add("es-AR", "35677b40ac8ab5dd5bae023d907b60520e1e1c56242bf532ab11641a33a295fc706f87c3062fb7d1c15603f1d21bb770225df6d487cbcb994c3eded6d96a8a53");
            result.Add("es-CL", "bd91cba0d5d6ddec9e28e456b02ba2de440f4400d8dd27038efcc4bb28884890f9a6c761d0ca3791443eb5156d332cda7b13168ed946dcc04d3cc467b3bf7daa");
            result.Add("es-ES", "21708925d1cfcad22b999dce5613d8020fb0f189a2c98b2d41558732539ae9cdfb862b1893a83337d1cf90a9b019d98671ca43ef801ea301425fa24a9299d64b");
            result.Add("es-MX", "79b1307c8327d5b2c7df8f5b6b99e0c41a5037cfe88d046802a36e42f07385b06d4bf99498d0601642ea1712ed87a92633bdd0c7b74baf2a48f8040c50e58119");
            result.Add("et", "e8890efbf10164d1700b64e4d86bc998bde47823f3c71f655b5a3cf7d40e2c3c62edd7be481563ae6ff38aae990a599303d545de20789d71d397d37bffc388a4");
            result.Add("eu", "c5ba595ebaa2b0e6fd655c40328aa9c5ee540e489bdbf7e1eea2afe8eb4426ae0383dc0715ef4a4f1d78607fd0669775dce4101df34faa640f61459290d268fd");
            result.Add("fa", "122a83023c76d605d4be6b1a4479759270e99ab8170644d6c2ed19639653805f6755ff5f6551de4d4f5868e43207d02408720a80b61013ac1ca5d557492e2419");
            result.Add("ff", "37f8825c3dba2ce2cfc8991c6b01176ac4a123e13ee6ecd69bedf1ee13dd95e486534d0f74c772bb512277d7321ae38106712520f974f4c036820b897f0c1e81");
            result.Add("fi", "3c572880a79b1b50318e16934369d05e44f151f350130a5a82ddfdbb779d62445b8bf6303cf801f14103ba6754ba173e3f04bc92c025d51b4ab2bc61a9b7e734");
            result.Add("fr", "2aca46fb1a3b4069cc1f28f79cd6566fdfb8c32e4d908fa9f6b57ffd95622be63a5f492117ffb44ee3049ce836cc97227a09b7036d87aa32e7e48d015c556010");
            result.Add("fy-NL", "270ba894ae2ce370dbf96be3a6999d7ad9a5d9b1b200dc29d1398736812f561fc52a330b2359f331527153cee65b73e20299c48865e75ca88f32f2ff3b8f835c");
            result.Add("ga-IE", "3609ccc90442da24de3cbc5222302af3d1db0aafdbda9c79271a3710d4e6e4b0c1ec637c1cbf0462acc5b0d24a38f5f39dc9e167878ad75dc7fb85f8c48c0f4e");
            result.Add("gd", "6e7b87c6d373e5a568fb7ca2146048bf18026943421e61c5bdc4baff8b5fbeb634d6306094573f7a20b4b60bd86a2294cc0e97d18b54fe59e697ae6fc1e5422c");
            result.Add("gl", "f645f2610370bf6b5d260536e404fa2aa832768a5398421ba3018052d40ba3bf5a004d183adb6ecc71db295db0285b0e3bd5eaf51d66c17ed8aaf8484ed45331");
            result.Add("gn", "a30da1279609aaa88c7ddc47cad7acf5b90a31d5bbcbd0d6faa8830532c8ea176c4bfd5ce69845dfdf16f115331b5401e37c4f022e5d45006f74c7ff52529796");
            result.Add("gu-IN", "abbfb3cdcbb23d456ef89f539ab5f829583eb94f282291db45d9ced319b3577256277efea1cbb3dbcf036b39d757c677894a6858301c239c6d6d1b600f0af770");
            result.Add("he", "8dd050105d1c1c8f672e7ad95c399dd02f44fa3ca40b3b294b41cca68a221ec53b8e78371a820a4dec2d6a2a8585a91b47de3f7dae44320cc2a5912da4137d69");
            result.Add("hi-IN", "9ab78b44428e364bad2d01820aa155c87bca4448773ebd9ca602256a0cef66b0982e087046b64358012e5c7e3cfd86d5295f0f42650548a39a61a702b469c874");
            result.Add("hr", "261ad4f8caeabcde5695845ffa7584d086b083a685f60f0def118bfb206f6d1cc795e6c809c1de126e66e4a1d15b2ed82e75c978ed7fb8d96d94df1684de7905");
            result.Add("hsb", "262869c786846889030a81b1b0f6553c2063ec3e9751f5204f77a2476155a7db340474e017e6a9ebee281d9fc5deb4df8b5f1445d6e15eb230a80a969461ee6b");
            result.Add("hu", "108da10ed1c5cab563a4a65dfb4ab19d0f1b4e2c1e23929a88a4e524e86a9a42897b96711fc38e326da211f3a24e7f03261b3ea80b5eb0aa8b6bce499916ab65");
            result.Add("hy-AM", "d71758ff15b61b0a043e813feb34b079d1f12959150c5a409c9b473e5fb811653cd94ac649fc0eaf9b86d9cefa08c8b2e3ed87cc14036af921000828ffb81b79");
            result.Add("ia", "7693b852e8fc8461d1e63ae152effd95f4cd7dfb2a7e4b95fadfe12d9d24ab109e1ea3db6a07d69d7f012632a0e87f0b370f2aa2acaefeec689c9894da5f8192");
            result.Add("id", "3dc88aada9a83016e10e720bd725855d9eca6cb0ed50a97e2e526f8dcf6732c2004326b30bb5808ae5149b8c3ea422b5fa60cb5954b2e3c6ce1ebdcfa6fd4a91");
            result.Add("is", "87a64148d285edf81cab44a386860ca244e398b5f422a4b915d353b512e75b01c0f001474d895ddea6e37422427a421fba8f69de75dbaa2adf880bee238b52fc");
            result.Add("it", "e4ba3bd8494d5973abb967dc8f32854fd37a4c16044b473d77fe6e9d388584a590d0a3954a4925fdde717274599551c36fedec3ca241cfd75ce6353d4d921dc0");
            result.Add("ja", "795f56ab147746d0ebbf3cb4f73c75400ec44aedce45e0f2300412fb44c9834fca2b796a82ac4749e9a4eb65ea7953f54c0706d7c4ed38a00b155f8366278886");
            result.Add("ka", "1b5e12a4e69ca0502f0e4807e3f0b90c4476ac432be512934e718ae0d36eb00887bba3264a6ddbaa5bb2b09bcd4ce9b4724d8ed26d7d2e6eaf617f56e9a6986f");
            result.Add("kab", "62e62b7a49541413518df7b5003c3a3dccd4fb1fcf32a2bbe33da3e0a822fd5f9f3446c50cf14eddb1de5020c1985460db5a48001d4a2efcb82e456ffd871e64");
            result.Add("kk", "cc4f39f35da8d2ecfe8d3da5b78febaf63f7738caef0055bdc7e06e190251d46de5e63e483e912f7aedeabb0c09df3deb332272cf7133c2a9d15d6618afd4188");
            result.Add("km", "cac31284ea9b86d4d098bfbc3b953228a014b3640d401f0ba94fff777eb44ee11c82eec6f095b2394ba651a00df4b2ce7bc44fe6c9abefd46b48de19a3735e2e");
            result.Add("kn", "5a4e2bfda73c89566728e47de27c4679dcc7c67c0f431dfd85016a59eb98f5c6d10588196f772f15c347f689561a29f4d5c4540926513a5a5df1ddb699f89958");
            result.Add("ko", "2af81a28ad186d324fbaacf8ad0ca359243921dec8f116cbd68acacd57d180c5853d9c3819334e04342319f5ebe3eb12d4397d23d540ff38e002812adb872748");
            result.Add("lij", "e2f4fcd80e7e816bdf7a102b63258868e5a222420faf5010a7d265653fe630264232c46fd29bb7c2b12ff0ac7a510d89398e1488661b614e0676d1fd9033ef38");
            result.Add("lt", "eb6cc362fe6cd07c218c60fd636b4709270c59a8f67330025ebb23a94c433191d84a4cd656a93aba322de0ed5561bb7e40aee926d49eea3e34770eb806f5426f");
            result.Add("lv", "5b72239329d4ec06e1d14fa2f4b4a01ed860eb882605bf999290c6bffbad7b50fd8f2c267880892a5fc88177b040025b45c1d47ade720e182025fed59d8dce8f");
            result.Add("mai", "df627a6c98a820b3788d0456c8dc74bb6af6bc4baaeff612a50cce44e2c010a4b6d28f7e4ee7bddf3fc2f4584793912e030cc5e33ad6092d8505bfa3048a320f");
            result.Add("mk", "9f68539ab9850be9e12de43ff7ae7b57399c4841254c87bb53071d8035937e69927306d97e17299e4fe556397ed871bd5fab2551ff29488b71a11f29fe5f3eb6");
            result.Add("ml", "6feb80f4a7c690e74253f8918b730a6d10795dd179028d160c16b99cf5ed1f1963cca5aea22c85168bfbd8ae9ba2dd0dc9ff9b5321b2bbb06f31621367401bdc");
            result.Add("mr", "f4caed80d6da1a82d37708efe4b8f298346bad7df867bb4de5b1f1c7e4196b6ea119d1644052c295dc1c45165d3f6d3e966c632c9ce7bfdfda8f90ff74637aeb");
            result.Add("ms", "bc563cc473535ba12e0bceef33f2bb901f41902ca26dbaedd33f2509ba9f47c4ec378d8140b7c7f0d42c7b42870ae8b8fa0af2335ea8f0841a48e733ae8332aa");
            result.Add("my", "41c2f450fb9d0587c51a765d0dcb741fbca4a8f2ff613a1e9f898a31af1ee0e959d41c5ba9124e73c9a5ff91823634da9f8f3bfd7b14cb447f39e5add9c4bb27");
            result.Add("nb-NO", "0dfa70a2e7d74af1b5b3140d8fd943d08ba445a987c032b46365472c5daf86b68ca8974c8dcbc899ea16437fb921b110bf20f0e3332d777cb1d7e6cfed870d15");
            result.Add("ne-NP", "66edeba4fbda78e8230cdcfa2004b52e21876feaacc238ff5adcfbe89bc6b1b82249f277317b2b8ca3d22ae6426632e1c4f33eb1ffb7b644799c109bca020f9c");
            result.Add("nl", "fe8b31efd0fbe890c0e44225152f88ba1e49492253823f09e518958e6355ad6bf93183f7ae51f5fc14785d9fd227bf996bf5e07a10560e3dd22d68beda803a45");
            result.Add("nn-NO", "42b0492aa167b6d0ec8708331d427f6b9377948e821d1c7844c113bb2186b669105a5083551cb94acd5123eed330d605c530c117891a04ed9ef990e3a9b9b210");
            result.Add("oc", "5e3adf051c3c4ea20d1f7b5d4ed561805cc6e6b513a746cd7db2dc291b8c3c7b3d3c8c625495defd00bfc87c7f08aa0eba8710e59da768f7677e63f85c3f2024");
            result.Add("or", "559ebde6dc126bbc794ecb19ec365ed62d80ce500f580316e7411b725271158243a81193af0c61da77974abe7b3ad66a8b881caa1810478d29353420fd63b8bc");
            result.Add("pa-IN", "f149ef34e593d67f481edc6c70fd8102017cc7c59a9301c321d97f4cf2c23430ff54da98ef7b416cb0454bbfaa462072e1692fd534a00dd13ca2955cc5208a19");
            result.Add("pl", "4c8c0644851c120edfdaccdffb7dfc6c9d8250cda58d323609cb0b378f329659207cdae2c5b32d6ffbb703922265f9e05bc8e81551d9b0619d4fc041f12626a6");
            result.Add("pt-BR", "8728a1829489012d079e79656ada3d2238c921d6d3df73e4b85d339372d0b37b41c1f9ab636e550736c01790c07a99cdb9f9781ef4133f0a781beb7ad47a7557");
            result.Add("pt-PT", "76aa71e793d461ed1d05dc3578b345bacec1526b835e97f28cef0366e14907bcbdcb7e18873b5ea892897de94b00537b65de19d90f923c2ca61523a40a612aaf");
            result.Add("rm", "03b8ab896dd6872070a9cb4a5ef03cd41cc5dfcb8c3b0015d3b3a0092ad214cd51937aedb3d49324ad032fd1dce769b9353905acf07ec58b83c1bf0815ada3ec");
            result.Add("ro", "4c26e9a8f5d7be1711b165b65e154926e246919cc0b7abe7aeb314a3d02c18721912ac8c2d04261b1b5e87c1095a7a8ad8e4b544dc6dd847b5de8dfddc0f2c44");
            result.Add("ru", "a5d15f39a6f672e12970571dc5ccdbd5003c4eda706ac5a4e5bbcef5e405662d689f184b632e909df958b52b436ed44fa646b585e93a063e815df4c19237d4cd");
            result.Add("si", "f18f48265b7bfc13843f1d3e9db4983efa35e4545ebdb4eb46e9e66ebe6b63da32b574f92049756563955c6bfd7406b64c73c1727b2a81bb08973ec0cb270c59");
            result.Add("sk", "462808fb5888314199d8b82009b06711190418175849358ca6e0595c5400dbbfa80178d11334c4563ec8bf3238971f189a0797482ebe3d46cb31216c63b8cef9");
            result.Add("sl", "16a90b296f4d89d5b978654d5f2b629c8063aa244e4ec23e49766237df218fce99fce254f74825a030431b60e065c525f8957c5f92f0c47d856f283e4a88c274");
            result.Add("son", "42a8253801ce4e6e6e6c11b923c6c72a84a1d7167b29da744851e07af888f3a0324fc42ac975bd45e01e38cfd7f381cd4daa3872129cc1bd1a2ac5455f50283e");
            result.Add("sq", "c1881d4fd0c62993d9fdd405cc2bc77038cbc0dccf8a68466cb0725ea6b4dfc411ae297e8a71209c3a4f2275034960b989de4d2d3c85c96e9c983fe03d998ac9");
            result.Add("sr", "7fc9bc1ad60a0100bfebe8818b53627f7a5051c186aea4d702b4a0e9e5ffb0360f72242acf370757624096dcb11fb0a7b74cb3ea299d0d1c194e92d8cb0765b4");
            result.Add("sv-SE", "7a83788849d3d5411985fef17d372d1d90f0b3920b04d0ea7027b0090e9f3e5b3b94f951ecf3c18bf1e408f3dcf3082eefb581176c436e4278376e12d79302cd");
            result.Add("ta", "97d6bfd8db2cd33c97e012216fb125f7c3c9936a088c91531ff0b9fc5c806490e16ea8fc45b6b7c534ab02049143a65dcfff94f90d92467e6a6aa0b5100d4755");
            result.Add("te", "71ad9d7e5cb2cf8ecaad956b1150e0839f6dab8242abf8ac5f48d67bcff85ed5fc091895683ea4598a874d8e9f330102bb4050dd56f6b67fd9cb4937befe713b");
            result.Add("th", "68a3a66557a7f060d2a734a28eaf4ecca0e5a66f46e69e463c331b874006c23fb1784e68ba310c96e02ef42bb44321b67bf4173ffdcf39f139ffaef637217518");
            result.Add("tr", "91d26ff687cfa0af9e55ff627380c642a37aa874cc78e3c64a5b0de141b565d255805ee57581c99296784938be8c5be5053fd4e06bdf0377b8112a021e3e3e46");
            result.Add("uk", "11829a8418805e9a1fa46477b2fb13e0f65950448204324bfeeb850b78abe3209543d6387e9e9c1614e26c993cdf61b419ef22545aff51d8eb678a944809bca2");
            result.Add("ur", "1b8682d1db576ef4357d66e5e43bb1b3c9e74a139f87933b8654b485eb1e0b0c13625a68ef914a4034e0808ab67867c28e268798c707f14694eabe9dcfcf9474");
            result.Add("uz", "3a2335bb82721384f45fd821826e3b361460ffa4db7c813a2e92fa7c72a6c539e4eed1b4bb79220bd67b295fca9edfb114fd07f18cd550f01b2f37982864ebe1");
            result.Add("vi", "86c9bc6d79fd0c69b7862f24311d0ebbca2703d2b5f40e0e0e0c0d338c2a95d93f880443b25c7c3512e4fc47cb332796754815002c7f8cc71317f83030403204");
            result.Add("xh", "a516ad2c70e1230d882fb4954b8890be647daf84336d176eadfa2e236d0b68fea516c7e639d07d8e9f3e390bfae3563297d0f0fe0625b5747a03d7cb9acb4ddc");
            result.Add("zh-CN", "e782a86db1cbef23868ff275f9cadfc8431ec813de47e2f0bd1f38a452fb2cdb04c3effe59dc70c35d4b356607378396868fc75a6126b0aa359d4eb102c0aec8");
            result.Add("zh-TW", "84ea0f0a6a934f1edd36050f92a6c7d402003e87bcbd5e4bb62ba025bb2f5abb0a6cb4978dcd9f376bb86853ede769d8edee278d676f37991e630009fcd40d5d");

            return result;
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/60.4.0esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "3f866ec8837c01079b354980407309a79f6cf31df474897d94e615dc39b5e8d3b81ff4b113e16fee405505347ba311e8303c98471b7f11f4381fc8bcb1fecdc1");
            result.Add("af", "5ec5442ba102641f1cc480a05c9bc77b3c1738b6f32e2701aee149d1222393163d6342610e3cb04b5b37760b2393f3d8db5187072632d325b189f0b3e83d3271");
            result.Add("an", "1cb6c1557bb99f934c10faeab00933816fa6dd95bed8052a7d49ee877ea0213f2c383c616a64128793cc248ba8599494e7d2be177868cad0158cf6f4b922cdae");
            result.Add("ar", "1e63589db3f2e2008201aec343cbea2dfbb796c526c95980985280d2da0337a685b97dbc1c8193c3611935d250c6c9832d3b2ab7f5b5cb7b45c626a482571fad");
            result.Add("as", "9512506feecb91d144e1540084cf8165c3b4f704ee3f3d1c6f1e7c12df37946e0d37114459abdca59849d26ccd05577deb42b41cad7efe2aeea7c13744d92db4");
            result.Add("ast", "e2d446df51cc17d3fcca26d29cfc271d41a43113207668ed7cc06ca4ae61c94c511690cf0b631fa9bc2a4c53e19c815d7b0fd265ec6968a7a28e8c3bc0316b3a");
            result.Add("az", "4885107faa9d5c006418d6a4f65787e91b1db19ac1b26ef6fbaa8e570dcac688dd59d5af671eaa4439eaf3df7ba9254b63a017e0ece526bc4664318f0e6672cb");
            result.Add("be", "3a538d323658a54617e1ecd9cf8a2e0c5e6c61cfcfe52043c22ee01207012b6006610bd315fa35f07849279d2bbe3666ed952d60d753b7a159c9cf4b3b330f31");
            result.Add("bg", "12b34525744cb0ba24a8432f8557bea0eadc5107e266bdf996d57c533f4134382626b1c132fabf7a6b157d9c1a210098619ca321907ff65b34a8cbcc16e42fd1");
            result.Add("bn-BD", "85221841ba7c4685050a24bcf0143c572d66e6011c4af6fd2602cbdf1f361ccb1985f19e05a71ee9248ba82eff822073abf94d2758d86119b43f5b3a47cc07c8");
            result.Add("bn-IN", "0b55ffcfff23d9f06b65b84165d29486483a5c5c2391352bd398dec941220879b4ecd0687f8ad5de6894d74799f5b113398db083dececf14d375a033b6039f80");
            result.Add("br", "5232c2d745e5fe982b1bba2187b3acefdfdf91525fd2d7a23b1f4fc781c4c5715cd5a8db3bc06b22f9a748ef0e00843317b5a56a174495416e9ad7ab813d49c4");
            result.Add("bs", "eada1ac20c297df79fce17ed872745b11ab4e5084f419b4b548f4ddd903f8ef99a858f47704c888c69aaacd997d30c6787524d963a4d922a009e6ca2078d9f73");
            result.Add("ca", "3174be72c8f49565e23f68754252997a0e258e10464651cd0e130d20fdf3b81f8430cdebd98dac722e14ed3eaf762bb4bbe5cc479cca989b12ba488631f74b75");
            result.Add("cak", "16d2342101a1d59eaa8b5b708a9029c2d92b8c957920db22a80652e01652ec9a9dea646d9433b35d271271c4a34598eb601e38aa9375afdc21ed299baead68c5");
            result.Add("cs", "cf0fcb96d204165e1a6fb077ca547dadc87347b5fbf3e02528d84c9eba056bc7a6de74a3ac2bcc3e2e67adf08c5d0b75ae0f8993e341918661f0e140302a2686");
            result.Add("cy", "c88c7518497933f700b66d50e3040c6813d2c885d69b93317d717de601f328ddccb1571b97c43ce1dbeb1a0ca7728c58829a46e193cc26df47e5048e1d9fa5a7");
            result.Add("da", "19710845bb4f4c8aeea40102945433ce3d5ca8d7065fc5278ca02f11ad8b5270f68b3f5884bde38cb6784be23777d09ad6ee9ef995fba3fcbb634e91c5259c5b");
            result.Add("de", "4105a41be86a5702110e735c08597953acd7c7354ebd32a0eb0a8d91cb16d2ddcc175fe569f9eac0a09a205b0eb36ccceb4e2746356f0e4c4d1557af877d19d1");
            result.Add("dsb", "44b420161097fce81f01e11d871c5392d1484f0a773f8a7adacd2df71add64eb87f1a2b50f8a7698425e6269812d0bb24e4023f7dedee184483879902c6dae92");
            result.Add("el", "c31fdde6223f11ec5627eebe4db5e2a1e5d4504fff98fc35afb54018cc6154e01c5b17822afb8ed1794ec575b86f838b21d7ca35652a3ee8c5fdaee8e9a49908");
            result.Add("en-GB", "d198fa64f7f1fcc22860ce2524e3493a1738246cd3003c0a8e7e1bd9807bcb2c24d8f09ec37cdc1d4729142bbe64a18614026ecd23434bb4045c24c6ebe9e9d6");
            result.Add("en-US", "c44fcd6f41b8f38f7fc2711ad79578d8482e63efdceb1b878a79e51ecc98d72c44b49aea5c1b17398f56b54c944a90010aa641e53f22f3fa1f83520a4627e9e1");
            result.Add("en-ZA", "8eb7797216f5e816ccde0f4a49c9bcdef834212ac2b9639409263a06824031e3cbb0183e747247035506ba1e1b62ae315922ed475a87ca51ba6f27564ebf4c35");
            result.Add("eo", "95af159f3bbd8c5bdfe294670f48dd8d8a51226178a595cb16e158719324de607a4b58a178a7dce8174eafe17fa036fa9c6ab8724ee11f4dada526c4a055af04");
            result.Add("es-AR", "26a80c232c02a0ea259616e30469f6a4993ca4d431f20617bfa71e5b938e79c22b8084053389f8030d109cfe1f6252e4994763686992d0efcb9a53720a5b14c7");
            result.Add("es-CL", "872f99297b5e645ad3d20f9f645f85264c74b533a9d4fddb1c63299a7c337511f29f66e7aa4c676781e9e73f745c1a2a6f44d197582a7a7ba2daa94e337e52fc");
            result.Add("es-ES", "84d2650206ce7df5be49bffd7c581f8f2ee74226a2434e81b7bce5e03f66d0f8ee505718b48fe218132a86afa9ba1c7f1e78109a87b9a870cba9afe124577d2a");
            result.Add("es-MX", "b4668ecee754843bd8efc4a99c921699f47e2f790ab4d9c6c2b6753a71a1d09f4d0a6e73cd9c6459dae15d738fae56e368510aff12f02f391a01fbfb141b3f90");
            result.Add("et", "9a79d41c9704831aeff15ed42ba40f2596178f1e81bd36db1a36fc384f28922ca72be556271cf0b029035736d68939aead737fee2b9dd5aa01936c20182ad6d5");
            result.Add("eu", "96e9f017645948b9170047c0cc48c71cabe395d5eb00acacf2b8d9d859a822dc4dd39c1bd88bc8d21f1d3bf530092a7699ffbca4fb46ff325f256412d170fa00");
            result.Add("fa", "c64810cf9df7611da18ac8ef52824f6c42805212f5c8687eacdf6635d1d4c3f9b66d7e5701b98d64b8e6fe3b8b035c984f0bc135914cbf5ba0fd08c572d1c7fe");
            result.Add("ff", "240348c2f07ddc4a764e1aef391dd9ce47f23ef2780847e0e99775605eb07258caa2d890ffee4807dade32a587c73d901260b629b7e1c1ad0e5c9541ef7ac4e4");
            result.Add("fi", "39f1c14376afe71827a12e1359d797e32ff356c1e5f0af6bba52e8a75552d43a09054b392f13aa157c7569cabbf3ccf346ee4b2270eb05a7353a2bb6f2f9c8da");
            result.Add("fr", "b42716b0b1a66e559da5e42ee2f04f1b1ef6ca5a86f54554b9e487489bcab63740cfda14de2b021b753de4485649b6ec051d32dcc60b4515a72d5f5df5d8d2f9");
            result.Add("fy-NL", "42506978200d990dac6d7ce93323a0bea17fd3c09cf81d58747defbfbfa4b564e6f6136d7d4429a2f39beb7e6c7f24d9a7f5794aeefc0d52a3f0865d92d2b44f");
            result.Add("ga-IE", "d37b21d0fc91626842cececea429246e1e5770a3155b6f9212db3aa2f9b31c9cea7635745581f8f6c592b0f3cd0163fa79c2da61adb3be82ddb80403b39e7b51");
            result.Add("gd", "8d40b9d093a2cf93a7c69ac846b214a7724e27df53aab442f89ce5b9edf818083bcde89f5a5aed97c84b8a37d84be9fe9dad970ce22f7a034f5a086ea529481c");
            result.Add("gl", "a97c830f2c1b856b7e5636a4227edf97bcead9be219e5bb04e47459ccff393368f632a188e750e837b5f72dea1e823dcd790a6fa90c55fd61ef01af128f3fe0a");
            result.Add("gn", "0009c404eb5e8804532cd13ddf08c88c4e60091a59940494c5d8d598e2a4b3630bbfa4c95a1bd25dfbfcba3564f92decdc7ad3a18ff5e3e7d520e8f822670944");
            result.Add("gu-IN", "3a25fa1ff4e5d9cdc374c51fa387f6d97da160a8e4658c00c745eaead470f80042564b4d5bd7bb0955bcdb5ee54f8f4ebb515430304a7c57925598017086e77d");
            result.Add("he", "79380403e2c013e476864e519c05e73321cce225bc81b79dcebbebc959e019b46c1f77495e3eb318d5a7c26c46f26238498135c1012094aca884001af6b4a100");
            result.Add("hi-IN", "2a8813277778778c7adb98ac426e6b42f3c69a6c1de69541b9566fed7464f770bdd1ab2986acfda3b07be3fd97b08b6990d15f7b37ddff01c4ad9d758ea53ec3");
            result.Add("hr", "b3477814cfce7d13d1db420d7eba9161d0b8ca739253dff87cabdf1ebf98cc39ee52021ff878c2eaf977837ad37598928d49d334230147ed07513270b5557de6");
            result.Add("hsb", "bfd66a88f1c07c751a706d667d98f3126dd348a0cdaf15649bea3e5097537733e02ff9eef39bdbcb660a3fc9b82e43c256174abdb41ea3a15920923d6e94ac87");
            result.Add("hu", "615ec3a9aa23a4d42c4b2dc18830c6f1f2998056ba617324c0f4578676a4baaa193b7dec65c5a383fa0693559e1e436194cb5c26f1a5ffd882cab5dd4a8cb2ed");
            result.Add("hy-AM", "1527f5783c601736980285e71aa0201370aacbaf82fca2a5f8757d6e6b01caf860c882c8dffe537937e613da3367bc1df1bf646372db6b861b30940a3ede3dfd");
            result.Add("ia", "d8f886a264d420af4d6c98052fbc0ccd92641efd920fccd940a9c27631d477140c32c2a30eb55d7acfb34da6955ad6975c9e0548fa4076c561632d31bf1784fa");
            result.Add("id", "c50d30d65fae85f22f8aabea45456b0f87ccdba7312c31ae80e9a603101a143a53c71994c051dbec431aa68fc489763399700df63c17002bd07a60fb5b2566c6");
            result.Add("is", "620facff87537afafb2dc6db367b9c3ce607488eebd5e1b5d022488234b9976047e8d32609bf46c9b7ffce6500095a45de5d78ec653607fabd4192d24b5302e1");
            result.Add("it", "7a7e557610ba3e08dcb242aa700c59b22cf84b6c22ab6d0c311c9c158f040f21fe4469ad18c9c0f2db43e1e2d9d2c0e34e83de4450a74895729238d3eb6a7f24");
            result.Add("ja", "a0b48fb03589400d402bb6a6830907fb6533f841bcc80799dd91427e9b884af54ca0cc6e3424750e9eb7d5ed8a9f9e48d6ad2cad310c483aa3e98934f66997e4");
            result.Add("ka", "e46e3463da3bb27c0fe69bafb92eecd9c605e8753b897b63478e33575bfe0f62ca4943c122fc580529b7107ebfffc60ef74fea213b85ac2bda5df6ff1150a958");
            result.Add("kab", "07b79540756ebe2d451ea271e3657a8c9f3c0d3c6337fb52aea1988000fe982f5185c23384f8d22f63c208c820022ec2387f66fbfd10b9583ada1b7a1ce53c7d");
            result.Add("kk", "92868c8383c0b286aaf03e88b426d1d610e7175a26696e6b5bc3a315f2e501bac5e42da4e478fae49eb72ff0b6adf9b3eae07cc1368950eb9b44a9a5f27efb6d");
            result.Add("km", "73d9f8645a93b6124e7855dc56d602f99fecf0dee87881c2da50c71c86afca78f215a610c294eb5c4566b48b4f8d62f5c4146abe75631cb696d9b4f26ffdf0b0");
            result.Add("kn", "6859e476d7fbb4bccacbe56b5b540b3e6cddda3bb5a6ecc0891e6671c33cf9696914742e10ede31fb20fb64d77190045dc54373c335b1d6478fdc08adc860067");
            result.Add("ko", "61bf3932df29acd54c7b0b8101dccde8a3c1d93fd37144a835aa24ba8306bf5e33dd04eaabc53b847ebac0bf569da090002f986dd631712226252b516a689d29");
            result.Add("lij", "7837de00dded864037c0a7aa4ea15ac9da7b802724c8340b1044294e1c7dad814cc6fdf847c55326e8de29c0138bcb187f4cfe88e7f8bf8cc76253508aa479ce");
            result.Add("lt", "7a369a824c7ab72b14da9e3706b8953155cdaa4a964a4c18141dc998c554f3bef49c674adfa585f7d42e098d263772c70f1a083725f8833ce50812197b071109");
            result.Add("lv", "440f68e3010a41c6dacf2225f1a17290ef9510cdd5655669ff54dc31ae7914a6dc2bfd1070f89900ca6f0f356f01dc051016c36558008d705019a29fe740b154");
            result.Add("mai", "12824b319872264a595000a6362b7d5362dfbcb3816b346c78c045375f30ccf9016fc2c1342ecf020e126f83f9d6fdf993f8518f2950966bb10aa0f786de984d");
            result.Add("mk", "95e28fbe799868872b386418e91df014c576d401fdceb24df548cc5a31de0dadb04fc37661920c755f569fd83eb8814abe5e11f40e3c24d0444486c49b6dc737");
            result.Add("ml", "646b07b9b8ae74a2c7a91282fefa4b98686eaf3a0c04e571cbbb83c862f82f3272f2bdb086e9bc552ffe656ee7c797d53bc098dc17d26f053a05dd31a29f5555");
            result.Add("mr", "3bd5a5c058d26fedaad0baf1ccdbbdd1eb23f81ee9021c0665d14d63d6b81ffd58ca43b8759d4c1396053b30242d92e178e4a4e0773f8a6514b14755fcfbc1f6");
            result.Add("ms", "761e3b3129540e039f6ec8e94fe7af203de88849950212d25a268da5f9dce17f51c6a56b3329e57b1293cc91e58929c4b7ef8e18b66577288ae0d2f83de6cfab");
            result.Add("my", "d8c886e56d057d3c8711ab4b680ceeeb3b07c9c3bd4eac0c467d6d4e7b43efb9863ffb2503f05591393c65d60b0528c72e70c9f4c85d1027cd73e86b4b232197");
            result.Add("nb-NO", "e22579c37c7215f43e80f456c134ea8f66e03cd668fb9a93726dbd635d8c186d541f4d94691145c8c34522cb0c5d7503741b6524568e79cf069c655d024795a8");
            result.Add("ne-NP", "c7b66bca14ac0724b1f63cc9793c2ecca62a50d5410586d0905df8bcb911e15fdb71d53b8ce91718ba90d94197e31c7142d2a3e676745334e9af30b97cf59f72");
            result.Add("nl", "0982e07b44e3ad0e06674e877621cca6426ffcfc590fb5b2a0c417bdec43deb84c5ce3ed53361adbf43230d1cc760a9c2181cdc836ff27159e942a90cdb62ba9");
            result.Add("nn-NO", "d5180f62136e62881e323165ce3f0c3ef46db4885810f568e3d36acc4f4504865fccbd5b9bbd2f7a3a6d7ac8f99b18bc66147ce07b556a0ff6831b7975ac4f97");
            result.Add("oc", "6ab404b46175d4553aed21e98ab0ef8138d8fe5e520664c9697759d3e24bf30f48cc96e718123efa359b03568b61efc9b01e8d2bb8e526d9e94f94c0b5210532");
            result.Add("or", "3803fcd0533359c66dde514543793a288610ebfe63100511b9fe24cb28a6bb0fc62306cef442163c729ea155fe55ec5860a13adb682d2dfd99802b115e010e39");
            result.Add("pa-IN", "4682e12579977ab0c6006c22f86730aa03e556149a1df29b1cf0ef0c2d131953eb1cff6976f8099ded58115591bc7995051da1ab407d2e980150c8c097199343");
            result.Add("pl", "e5c0d9fad9bcc3ad8508ddcef93601bea5ef962d7da361c11036f6c655a9a0c9e16a969ab4d48a1ddb1a94be552fbfe773aa9b26fae73cb35e90fedf58979cf3");
            result.Add("pt-BR", "2ab5e164dab0efbd363f64d18650eda96b9ac3ac8ffe193625570f43eaea9880b847ddb5376142df99f9fb6486269355cbd2886f0bd363851936ea20fe803c78");
            result.Add("pt-PT", "a4e65abe9d070e8902f3eeac071c19ee2f683974f23c3e55746b30440ddf45387623de8dc3f8a992b1f3ad4eb9db7c3d168ebe7c77acf105188c50c978951a7f");
            result.Add("rm", "8dc424b71038107a5241d3e0f75a3aaabfd469dee74463863cac4d60a181cb25d77e4fe3ee90559bb333b2587f3e276656f405500649f0329240fa44b14739b5");
            result.Add("ro", "66c7be94e4ee59c370719f2834784943d3e718ee0131bc06c8e06320210e7663a9faff4df413caffcf546f6aa1bb39e77a9632503915b150a738ef5781384977");
            result.Add("ru", "63e698087640b9116ff4d8bc4b0784172de774236f13bf5e03b02af93cd073e40638ed8d1af18ca187c79ebaa17ee23d4b060695363f9379a61da7ad3521e43d");
            result.Add("si", "ebdd6a6dfa6d36ca3065cb6029d4db865202918436d90325cc855abe100a3b0f29c174b1e7bbf4ab4d64a72195bdeb83fb8b6b376af51a164a11f05c960fecac");
            result.Add("sk", "55c313d4ddc9b628ee95fb400281089f7b7141fc56ee0e6241e077dac7895388a3fd81f26b94c48996e5eb32265cb334b9e673a6a27cca25eb630ae3cf34c683");
            result.Add("sl", "0622ab60cdcae683b7a83e2ac4ff751ef5e0fb2f6716fd159ec1df2f4761506271bbab539205e612aac66f8389d3bbe8c8b901becc4ae13ab38dd960a8e95cb4");
            result.Add("son", "07f3dec753808e3501309c756d7068316262f4c83cf2d12b21bfa3fbce2b78d3d773b6b76a9e1c039a83441db80d1f03ea45b25e974bc8ab23474564ac824bbb");
            result.Add("sq", "a019f34ad096b5aa42ca1eba858112d034f7f98645326774ad425dbea814977e652800007628499e5bc052965bafef224a284f39b06748189962ba5fb457afc5");
            result.Add("sr", "3f11aea1e7248c2bd98931bcac881af1b90d8f206bad3bab32b572ad6d2f332d53f3228694122a5af4b7adb6d37cc57ad863750a8f674e992a3531653640a392");
            result.Add("sv-SE", "b489b72840d21a5af7e536b689510f06d625b8b19dee44cdc1cca807f422aceec50d5b6c9e73d69254180731aad58cbacfeefd8706eca7ed04d821f2d4fdcd6c");
            result.Add("ta", "ae638d27c2add7fbad995b3028f86ca83b9a86091ff86f759856bf1f6d0f41f8e87c337dd3747d9a7e31891e1cf876c42557c1c5ae06e3197f746a5314045489");
            result.Add("te", "bd9c6b34a1b96e71819a7bcd2f2be4ca06659e34f4eff3207c9cde277ffc1bda81207350e44ee2f240e2df734dada2c78e6a4c69ca42de494fc78c9d33b898ab");
            result.Add("th", "ce083e0b301f14a209422cf8b6626f3ea05ebf95e9142c6b9229349a7d251bf19014f55e87f6dc483aeb653e262117656441829bce4bd7cc02ec00ea42d364a0");
            result.Add("tr", "e04722513e2f95f7258660639c3b80bde5c403fa3e3ee7a9235878a112f2373c9896cf5df3e5c41280637e67617427c9ce26e24d91962a2fdb00b3cbacaad1b9");
            result.Add("uk", "9a14742e13260938f5ec329cab63573ec0b12aaada8f7366f6992954f208a8d110294b21d65ec878825c7a8cf5f43f6f724d2a2ebff4572b795d9b7dae35a82e");
            result.Add("ur", "ddd2bfa4cecd164442f615b3a866b1f945aeac2ea7de7a69b63b1c1d86c1aa6ba11fc67ff9909981e56745cfc4e51828198ce1fae471f3ad58917838560f5ca8");
            result.Add("uz", "e835a78d05f614539b6d8aaca023da1c84e77bc58e56a08d287199092c195507760533f3c6c84faeb695d51ffd61df6fa22e3425d0fb2a6a22f6e20194e9a12d");
            result.Add("vi", "7a57706c8c9ebb5afaa2aacab410092b9fa458901c43bf20701bb634c2c71a550cf9aca6240ec8bde81be8c21478699dea3dbdbb8e1c8a400dfa4eb9512ba282");
            result.Add("xh", "3bb3c003e6578b217003ef7b66a882080f9e7d2d8a42fb65b474d56f5c262506dc8e2c3a2ae7d8806ef0112cb9924fc748fbc46dda0f8e67f6c3a2679cf3c44c");
            result.Add("zh-CN", "a6d823e6a6505abe78081703e0c08c5f8bb38a12618bc38ffcb960855618fca02a88986dd73e8476d4479095717c8fa63c387aff9e370408fa4133308e58eb6f");
            result.Add("zh-TW", "f8267bdde1a7acdc6025fc679cd03f25dcddbce3cac3077586b6d49b8beeff1a653ea7f9fb91e50c669e216156222f5da72d79ea9c54fb1dbc5e0cb3ad33dc6d");

            return result;
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
            const string knownVersion = "60.4.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    publisherX509,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    publisherX509,
                    "-ms -ma")
                    );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "firefox-esr", "firefox-esr-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]{2}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                return matchVersion.Value;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox ESR version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit an 64 bit (in that order), if successfull.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/firefox/releases/45.7.0esr/SHA512SUMS
             * Common lines look like
             * "a59849ff...6761  win32/en-GB/Firefox Setup 45.7.0esr.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "esr/SHA512SUMS";
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            // look for line with the correct language code and version for 32 bit
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value.Substring(0, 128), matchChecksum64Bit.Value.Substring(0, 128) };
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be update while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            // Firefox ESR can be updated, even while it is running, so there
            // is no need to list firefox.exe here.
            return new List<string>();
        }


        /// <summary>
        /// Determines whether or not the method searchForNewer() is implemented.
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
            logger.Debug("Searching for newer version of Firefox ESR (" + languageCode + ")...");
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
        /// language code for the Firefox ESR version
        /// </summary>
        private string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private string checksum64Bit;
    } // class
} // namespace
