/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020  Dirk Stolle

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
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "E=\"release+certificates@mozilla.com\", CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


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
            // https://ftp.mozilla.org/pub/firefox/releases/78.3.0esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "58d2ae8e804714e22a809af24444c8702b5bd11f5408affe39a555cd4017db4eee7460be57bfd2b10553732fe46c927c3f2abe9fef02167a6272f389b5af5870");
            result.Add("af", "47ea0e601f6061f292002041d45a13822f7877bf365c15e78680f5210b85568d46e376c75bcdb6d272d5711dc1dd5a0b99ef7ed932d64840f743f0c181beaa1f");
            result.Add("an", "aa648f3135f118aaf1a3de0d2d76ed909bc6191e7e22c2c8ef9300a586380c35870702725e732b692a419133a811099b6ece0dc68fcd764e9a845c59ae23109e");
            result.Add("ar", "64c45920dc22dc73eb90c8cb4e9a4611e88ceed805e4dcd311eb2cad0308a5089118b33616a2a8cfa31738ec96480f0a9bc8eb69cc8c75b28d70beac727274fb");
            result.Add("ast", "1a7f80ec5da4911fc26bcc0a83bb4a75a28246583f0cda20bda0069845fd94dd16df6b60b8deb66e848eec12d5366d9979c1a3cc6a6122457619bf563e84c97f");
            result.Add("az", "44b9785640e3e106ef156dc42d14e56235a6ff0d6b7626d3318837e01c49308029ae6ce3dbd1891dfb5ad607b917a7d7bd724ec4cafef2e218b4570a0dcb6c81");
            result.Add("be", "1d1867a73860fe3199057586d6ccc6f427c3cc437b940b14228c6df556061e8a1a976e58b0d45af45f21d06558615e62c6292f593f92df1f07a5ba0de89358fa");
            result.Add("bg", "08a43edb150f3aeb65ca1698424368e81a6f9f46f49c12eed13caa577403cb88830e797f72c823c5166d45f244d5fe635d66a52bf67bde2b92a00c7573587d0b");
            result.Add("bn", "13ab63b023495b38b9524ffb46795ded7d87c6873585ddcdf9d2dd8f121ba6608c11d05a67c8be7c9d65d1a26cb58554592792960f2f448b15268f20e2dabaf2");
            result.Add("br", "137edbeda0b79f625102f02a059d5f60d1ebc19bb59646d8183c5163e8237805c5904b44f2a857902d18e4ddcd1fd5a09ec3aeb54e2d46acf9e1f27a6001ed00");
            result.Add("bs", "7ce0e4ce8312920ddbc1685cce59ee73ef7321baf086433f4ec80185056485566c1d0614889b6fea61665849534a335b8bba2e7d03b037e4673808186fb1b57b");
            result.Add("ca", "adabb065aa3750c5535b52330cbe5a95091f57243f4fb9d5a4fccab3b61ba8fc6ea17b89eb3b3c8a1f72ce5865b4dbcf99f5dd74562ec357b5e7e3aa77414c74");
            result.Add("cak", "ea6cbf673f5d5c407136de819ff099ae0a1e4809e225e345b419c93f3aaf995212e6c581a5f103697b4a1282999d890a54af1e440727de6b70495f139a140ca8");
            result.Add("cs", "023bd9a1bee24d727d8d8490b0a3aa1b50702e3f55cdadd8d0d5dcba0c6c4fd4d85d4938691da31279d0d9e5e4bb628780df2071f1037dcdac56c942ed283ddc");
            result.Add("cy", "b2e94c36b8f23f0597efa26ed0e414bdd5492bca461906702c3ccaf1dafe3ca2f0adf25b1da61445739e99bf62b705f147a48fe39ef866324a301e553700da5f");
            result.Add("da", "d367c7b7a57e8f74983e81308b9a5f88935358e83a084f7325a3abf846b598bd1260e1db702f35c9cf3ff6cbd48c3d3e6340f1813b434a1fee5333e73ba7c754");
            result.Add("de", "04af55763c877b8dfcc4b5f798d615769b66053079e809e86a7c9565ba3f1c2a448aeb7f2de1007683c6e906f7d688dcba8f3b18ae001fdea51c2df419a92d91");
            result.Add("dsb", "efcec304057f698640a466fd021f5365fbfb3402034d44fd4a1428668ceb56fd42899c771584c78a48912baef099720e0a5177c89225845912efb580dcf8c1e3");
            result.Add("el", "d6bf57a81788febc6a357168217e9c1d64024cf08808c6aef4f8996e920c2bed57d867b1ec474a12af66b88f78c73e0c0bd8dffd98824fbf5b816e8878690a26");
            result.Add("en-CA", "6d883307a1026fe61f69a5b4bb62e8f8fc1e3e2aaa245b7cceb4a26666d6741df327462bfe1f3bf94e27e79378903f06856d9b049d62abb83652382e59454710");
            result.Add("en-GB", "c282b2bc42b5aa818d779b7ed64822a74895dcd2442be04065df9eaf30f8f71a92d7b0e7b5c48c7e73e7b9f0a505103f6ebae813c1764756b61fca1d4adab661");
            result.Add("en-US", "16985d331d56d168d43edcba8d8ef3c706a4088cadba7f4a65400ca8c68f1230a176786f55ce40c7f098ae8980f88edd6b92282acad55907b0d1bcc99561786a");
            result.Add("eo", "a7ca3dd1b253f65aef22a27c35f060b3e21ca5eedf9f0f5a103ef25ab9a5220c2f5d92b249d8ae2409024f25a2a162b55295749f33420f79db62247061c83007");
            result.Add("es-AR", "a79393ada7d3eecc8d5e929e1d4c0fb4d82e6db5316bd76a78860818ed0d1ef6ac56eb9ea3c9b998a114fc1e4fea23b8027322b590184fa64e122251f075831d");
            result.Add("es-CL", "5a8a5dfd8692db82461e374bb0d37af8949f7e27f092f6ffea1436accc728d92de10c5aeb8c488396f9199d3b148bf092b7f1cc97e6a9a051bee001a41318bb3");
            result.Add("es-ES", "908dafea59433cf4c041398fa49970c385bc236d4240f0ba6c42883e9a421100cbe17650d001df47d102b71a6657a5f41cf11b60d5832e6261078546732389d8");
            result.Add("es-MX", "be2fc5b704b1828bccd2c0878e150058db4f3e7faf4cc521a44440098b6b766d327204d7d568ea81b5acdb68c4a65c066e761da0e42255b10a8851ac36609bcd");
            result.Add("et", "5a9f6240e59e941ff9378b1adbd8e08e1ad4e5631476dbec774ee9ae38f47539a3d13b4c13da3cb6f9d621f3d4348ffa473f40324ae78ecdf102c7fa3bdb139b");
            result.Add("eu", "53a5dab4cd47498f3ac03560c59ca372d499d3fc508639157ccc0678a0a2a0840574b0cbc04c7fcf96d3750f07a45b88d5d8a5f197a63c43b8675db419c37cb7");
            result.Add("fa", "1c7b16c0f5820445402f5b3a1772501d9ddc5f6f44fb03cb61825017e6f8f93f79c53c91d1c1779eb14e86af6fd51bb0dc1bc9174419efd6495f30e3418bb558");
            result.Add("ff", "f8245b163bf288b7612a81d27637a21cf3c00249b94e3bbc7993eab326a0ba5c69a9b61dbb83463793e1b60d5eb18a38ad05edeb7995356bc87f90a834bfbe2f");
            result.Add("fi", "3207ab229715f77186677b9cc944cf9fb9b8f688d955856a08584847a6c08f16b78f333d1376bf831d28e106d5acfd88d2e77a30028481d4c868a25c6ca9b798");
            result.Add("fr", "21bdbb70439f2ca76af2e1fc84e2c7731d811cc5500bf50a9ced751669f930e1a4899ef271d2cbae9854244cf32d5c3d7083242dba2ff1b0baf798dd61bd9031");
            result.Add("fy-NL", "898f90d7d9c58a90fa90659b60408fecbac5dd811e43f2b46ead21d6105acbd8df7698c78148831f66907d37f5a2d013508cf96e583195d2641e29bb2f64ce93");
            result.Add("ga-IE", "e6a4b0114126d198f3341e376bf7f48b82e77c881e51c78004186eeb365c737ca30555708a05dc709a6e4ad9ee926c9b25505e8fca81bc129dd32ce83287924a");
            result.Add("gd", "51c77d5532c3b6279cab17d21c4418a55607ce5aeff8a5f038ae57216c616d38dddabbe23460d269b6380f45921f00dff6a0bd6ee7470a00c1a8b6bf87c8e4f8");
            result.Add("gl", "c3187cf9bdf23233081c71d60245b630f0a598dbfa1e90918af9d1dc7697432c92cbabe204712b1aa6245ebb789225678be58ba5445f67ee338a6c0cab8b2041");
            result.Add("gn", "ddf6307227f0dda86898fe2c06af00ec0825d5359957c875afb2bd82cada3880a11f9bdbbb7025c3da42f7e472dcb765c3920aaa29fe05ebeb88cc04c703d419");
            result.Add("gu-IN", "0be8dad1eb1d691c01a3a53242c7df5dcb6d02077acdb121c6d3c2ad1c9522124a50542a74d6353c2b6cd87f3b1e8e89a100366d9c7a634ad7277cbaa46b63b5");
            result.Add("he", "099da7cd55ea543dc1b2335117e1721e632b3b4946aba35af6ce7ab7a25131f6ceb00cae2320d11fd80ad8e15810be7b1021a316794d8d902f7c622170b20c12");
            result.Add("hi-IN", "ed005f2d8c1e47c3db964d2512d19ff54e955ba0b5421bfc0ba52dc5293daaaf0a641a9feee2043727b86b070670470f975dbfe6dc48a657ac0b2ac058c6f90a");
            result.Add("hr", "9a4c2884fb60887427c6fa5d7ae432df09c9ac6c0f9b6f62cffed64fa5ad85379a2194fed1d05c4a643ae17068f72ee234029548ec8dc8ea84e94b5abb87cdfa");
            result.Add("hsb", "0086402edf93e9c2ad4a63e8f9e47d0a37d0f7f1cfae661ea2a6c8569ae4cae1b03d14d2944f2045fcf5d4a27905d2d38e22cd2163a60ef0db70356cded4faf3");
            result.Add("hu", "89a49fabc3e0f96e128c7fbf2f88a17d0fdd77cbcd8b7dd19bc564ce93feca516a922ba98897e0f682779fe52988779018e7b541c3211ae4746b44b0c26e2dfd");
            result.Add("hy-AM", "daf716ebdb7474d37a2f46911a96d023073665dab5a2a074d278bb2d27247720895fa7aa61c972f26cb8c38c792c8b5c3b8d8d9aa424cc602362ec1d2ff5a781");
            result.Add("ia", "7b93d3b27942a82de59f8420ece278edaeeaa11342ff16005e0c89ff31c4ad713609b05ab76b67f93476a3f6cab71c9dc5cf72ebe4af6be98298c6d9b92eee92");
            result.Add("id", "df4085ae5f59e62a1e1464c6e6ac5a9ae869287c52fa77d2f26e26c0ac536f9240d7391ffb67b868dcc5390ddd734e49026e114c25cb4c6e332c6cf850a9eebc");
            result.Add("is", "934b0e45733b7f7793b04184ead05bdfd302fc7145fbd96cf8162fe306f585306db5da599e5bd5a8fbb5d2573d9d8338ba3b6304fd08193e07d808b5114cf488");
            result.Add("it", "cd056e234037cf0f6328d1c1f79e39e454999e8b3f64e2aba3d3072c33717d20eb79b559e4d595c6279b8d97c8061211d7a9d716463f404921ac00b1b851ea56");
            result.Add("ja", "abd3464c1a5085e12719f99293d09537bc18c6fc3f1160843f6d3bbe4948543cdce82d50c83a2e1fbc8c3f045a8c2f4034f5cb18fb260a76e2fd5ddd765c339d");
            result.Add("ka", "999bbe1569c9523eb694dc459d1a0db98e383a0414e2e29125f51902e26683dce66ba79a668cac483ab96c1d6b34ef992eaeff9491eb81d87a709db2c32cd075");
            result.Add("kab", "a9aad4e6b352bd7811108346fd468385b657dfb0ed0f6c89ae8361a093326be082e816fa4682d42f4af6c68373a1dc7dae7581a978632c67929da2385b4d5fe8");
            result.Add("kk", "7224b60109eed75a3d57a6145314690e673858b9169b1c76bbe2f66e5d22ccf246558783123d1d539629a23508d3848180dca71a136ae8f7d51eb4cc3a690b88");
            result.Add("km", "b98a822a13f8c9e2e574f2ecc335b65f9da28dd6e443562e8339777c2c7aacb3dec06c75616a0c21e9db2ed2326730750f0be388b126e495460276a51c6600c9");
            result.Add("kn", "86859ab129a912857300cad554dd618be04c71e4f335b3926fb55b6feb8de69062ec64fc2f41663e7279662db3114f6c438667f6ae912a2b851b877c9f47a077");
            result.Add("ko", "869c8806b00ef09d99c67a8ff71b3a3d61fcdbd5440d6efa30abbdba973b9d0b3d8a7fe2d8b22b1b6843a67da9c2cd4ac1c8baa4bc79b23eccadf137170a8aa9");
            result.Add("lij", "3548de1a6acd6c0dcd2b4e9144fdc2400471870e63bbe1bf35c2a6966e5e5e5cb698a40e795b1828e44dbc40062feec82fd0c064bbdd351d742ad4756faf7e6e");
            result.Add("lt", "1522189efb19fdcbfd3e8aa12a9757bef61350e2e56495062d7a39b7652cdebf3b8ab91c6a36c4639f339f666481be68d209603a5130ff378efa98a2865b3b3d");
            result.Add("lv", "834f7685a380e666641824f6b28ecff054e3eb4a7644a0f0e391e4218d3fa20b54a6b7390b7d873dd92fd3a29251e0f6bace8e3245c79f6c2db22bf4b74f6f73");
            result.Add("mk", "0e1bdd97d980d2303119768a929165e43be3fd6bff0bba20895c9160b6812aa9525bc2008880a6b6add33087fa28ff5dc7fe2b571ddab1c888b3425277860084");
            result.Add("mr", "a36a497158ee7ccc3552cba09f617cdcc29b78a2f3c6c8c6123d61f5033c72808e1f53f6048ff90d7cbd179517b01c224ec58f724116410d9cf5d2b96400fdaf");
            result.Add("ms", "f87341452918959af0d4e98a81a7dee46aff22955355d00835049bacae7b84330d7ed12f122c17e38a84a4702d6ca3c5d56cc5c69a663e942ca7231a104862ff");
            result.Add("my", "e144b985679aceab1201ae4656eb9ed0a0bd251620e7b633aba0c87457ba5b5cc08691a68ea3f2dcf946fae1cc59b9d02e58fac5afa277d30d0cdb9a9e1b3404");
            result.Add("nb-NO", "b8ac65ac4bb8c03eec0c871d76654dae9e6f5db73529ebf5f6af866fe201b4616ca9f81bf64745ded2565846aa9c14f475f252efa68da6ed5b371d0f23ec23ca");
            result.Add("ne-NP", "19710a475860ddc1f641b921ae8cdbd2dd65af28b4bb348c03e479afdcb84555cd1d8b91520f7e5b6cc6fd6c3af16067075587e1cb0ef8fc59ea8519fd532f5c");
            result.Add("nl", "78cbbcb85354301ed5feee3b6704144d6507bd80567610cfb024a53b295222abcb44d128feca8ad3f4824a4a2c3b983d4d3a902e851be17e186ae198957daf63");
            result.Add("nn-NO", "1917253504186ac9fe651a0240dff809b04c03d8d5cac50146f5ee57114dd0d01515480c2b60cdeb0314cff7901eac19be7d2eb9d0835581e337960259e4b05f");
            result.Add("oc", "ed33da51794a85af3a8f59c2b9ce98ddb3d300d72c335b1071adc39841f90f769ac11239f90178926bd7f5846547bef555d3fc613e8262973fb74a9bc7dc2c2f");
            result.Add("pa-IN", "c6fe76ba1d7498a2f2bb3ee471889acdff411fad0c55462758e888b6b0699d586c02d19e7f792c27e21be0f8b9790e92087410e9a60f09f9e5e7063a425c9b16");
            result.Add("pl", "40ff50f04f379772b62daa6a5bfb80f6d383a79d62a782ea929bd32261f6672fdc933e480a9519c77b27d9553c1743a4a6e66025b1da9a93b1ca99b3fceb204b");
            result.Add("pt-BR", "b0cf751b2951aabb294628fbbe5b62ed337d9f5faac84e3bea575b137106dc41230fbdf42f53ab1d17df3094679303d6f7cd4b3f5130594b3222cb43e99371be");
            result.Add("pt-PT", "ff917df0d83b18762e4558973adbb00aa7e5f0c2776dbbf299960b3da1809934883d741c53cf6c554ded6c8b2d36fa6d4aa472138e88e16a1fad3de5cd46a22e");
            result.Add("rm", "743462afad9e62ddda7dc1218ce0ac036bea6369f7606559172493b4db34e1b893fb12c4fe03ebd715edea043185ee248e9575864df1a1f357905285ee55af55");
            result.Add("ro", "25ec399cbd74c97c1d5260789f6ee7f4ce277f821dac4e5aed1d5068d4f89ee07ff3f7ce00a0c9569ae8249162ff7a9dcaecfb10253372fb8a205c2f4bae9fa8");
            result.Add("ru", "03130572ec832f48571577ca2b414b40e0a831d06aa353c5373c0d69ea82636aeb97618f1508008667339b96e0dcdf70a3114390607be5861f0268b7b21ab329");
            result.Add("si", "321cd517889707df02e55e3c1f07901d8c9c00c5bc6449b259fcd578aea87448d6c5a8ffb9f228969da5e2005042b5f5daa9db7f662a2bcc7d2187d15c2b1548");
            result.Add("sk", "1751869d53aefb5bf72e71d5a19f1dd7e5612afc8d1b8e98439e81e31c979ade1f92ab1ed2cf4572d3b9ed933a2fd87f13767d8042f59e814c1267c612ca9704");
            result.Add("sl", "3d2de7b029582e1a824fdaad17f1cd6277353d3673be7f25c362fa115fd43d234b016dfe69899e38883de3087f31cbc678f22b5530c2df766d613814111f93f9");
            result.Add("son", "7f607d0dc6d90af0541512032944cbde0644137973d34dbd9b91c4eaf2380a21830ba44994476755becf5d05143cc625bc6469e355c12da5758ccc1978d3c40b");
            result.Add("sq", "6e84c4693ccb5931886146b72464705d6f6f4c7520095f8a0c61b9a319028c062d961d29038466e6f534069a4149ffdba02e8ff0981b6b82ed4e1c409373368c");
            result.Add("sr", "b5a8d47707197c986cc0b218696b5d891a4f343e98290e014ebf459a98cd64f28ff0d62d0b9e15218b7e5bbce6b53796c4845cf0ba03c142c4d7cd3e2bd2b826");
            result.Add("sv-SE", "318b879ccf2da7c46d0ce2b8809e49a9f5c8714f72ae50625e34d3737e89d7e708dbbaa1edc29a1a2799f405c2661d13cd076e946d758c828e0b4093cf587b2c");
            result.Add("ta", "c6559a440fc2aa85c2704534696fbb413b150f1d8b1f52445d908c34eaac3e5c56b536e690ae38aaa98abb9fb87ddb6d707d458b326c1b3453436fda05ae023f");
            result.Add("te", "8d6a3cf8806c3a6846da49bdfff5d236055d6be09f57c514b4e9036a8acace4c11386e73839f658c24921aaefa86ec21e222cd55a97a87f714abf3d7ad36ca86");
            result.Add("th", "ff07ec54e816cb75528755c482f7cc4b8aeca7412431dd5a9fa6aa065f0cd15c192ef1aa4cbac255911e70b8b7904eb5ba8361c6dbd2051c098763bdb8ee018c");
            result.Add("tl", "eb294f767f3f1c420c1438e68eda56cddf30d33b00c383ee9d46db97b1d668ce01ee50e241de50803c6b7f5b3f6d9bbbc939f750f3ffafb1fde445ac8227a2e5");
            result.Add("tr", "443a088b742757b0950888a76319e1220101ee3b8ecbb444da9c02c54feee002585dfe87c4b26ed7614a2e5e0c7f79f6a15757f088946bd3f9b5e7e370321b66");
            result.Add("trs", "baab2cee74708d65a27808213750a364c2aa451575fae62b922219182451133ffc89c7fa31b12260a1eedbb711d5ecad26405a56974e161500e6bbede03860ad");
            result.Add("uk", "bb0a9826e8d1ffa68c1f5ed4be919862e6b15706720eebeb6f6a04271100419a6860ebfca0db3a0d3aa8d3b9a30301d10196c5aa433928822f3110be6df3dae6");
            result.Add("ur", "4efe1d6af43022aeb02c0d29e13f887fb58556aa02d2f01f57ca9ca41edcd3fa917df1b38b4bce31f358416ce4e88e354cd40b1de7dc2eb11b923337d397edc6");
            result.Add("uz", "72ac644c87bde20609f00f5127e6b5fb91cd1b27620eba8a05c2ef77916a6e220c465b1e032d3e3ca94f0df79a2bfd01d92d965b5f4477e48c3043394ea19ad0");
            result.Add("vi", "42a9d56ab0fb2f5323fd5bbeab3bc543c8f2406296d94a1ed78845488fbc61c9020e27fef5023f0a5afd2902db989ada6e6cce1998b6039d832dd6a37dde315d");
            result.Add("xh", "d3bc4a842f5d4d9dc25886308826db0717a8b4fe61e0bd001bdb7c8bb0693d2b01c033188458dcc063d4b8637b43710385f876605acc6789a68641efe1548187");
            result.Add("zh-CN", "452823e30e766f893f2b9174e3ecf82f521f01f2da8594afd9d7fb615c94fa083f75fe6975e5bcecbcd15734396627a88024029fefba5a4d2f463174ac8b2bae");
            result.Add("zh-TW", "073b4c4601f3f07ca3203ed327fdf1965bcae851a771f05b02a220c07c86f43a1740c78c0a7ed86029c65a46778ef94db54bc39d3b4f752ee3cc7b3506737873");

            return result;
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/78.3.0esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "75ffef2b3319fa9fa398306136b98d4493f2df4712ae26baea140d381c4394bcef3a9a5392a4f786eacf0420b9f36dbc86b0e2faf464c065b27fd26032ea16fc");
            result.Add("af", "ec8baa3003e75e7d443a940e9f1d8f75107aeffb0bb83d79543dcf1d8a1bee90a4c5b83f2db9b784d30eeff2961928228423df0e4f00cb8c30b30da174324f26");
            result.Add("an", "4c08d34e2a2e452162b4417e4cd01f5208f8a7450cab2dc8c1ec3e2494d5adba663733590a0846a85160a787b7d443f09d292a3389f345d0e816fe4a2c3452d9");
            result.Add("ar", "788fbb47a82b5418a7035509bb3cce2895d9247fe56169184827dcc96d93cd4042bc6db3ebc88bc353e09352e39b66f5da2bff09c0593ba5acb97a3328cbe220");
            result.Add("ast", "e48007bb7cae4d4dd4236ae1363e33c4d24ddcfdda07b43b46437ba7d76eff7ba78208e4fa8e290f592c0f18e5c60557a22203581547597c2db96e8f483f7a8c");
            result.Add("az", "ff1f6499c1b7fd66b607b2dbf8dd501626e7bac15144ae2cae20abd29e8061fadb8b1a46ecb9e70b537811929c1762b5bde90c6175932114ab6e69e193ba0f2a");
            result.Add("be", "56ebe20288403bd1a3634e5d970703def5f307933f1e90ea058d681f3a8a880356869def81db61fe5f84ba41d585a8677fd583c5d0b3f3e4c8aa75d9c912a268");
            result.Add("bg", "8a79506b31932203d0da065922f57d7d805790fd04a072eb6d33562f8351db0e4c23b553dbfa47378b2204d60b02fa9dc007f841d62fb15ceefa8a0fe2729a69");
            result.Add("bn", "6cd1a6f8d38c9efd34c3c869388e52d8ada75a0a9e5202e0baff396a52989fcda66d3541c8bf4c6acfae612ce9f9a129039b2a7b245b0eaee8901807f468ba63");
            result.Add("br", "677bf3034d8bcb18889002744431d2d6a3b149c4f4640097d01875527124baf003fc2a30a66277082c777dd32ea95bd3d724a52ca25e83c46720d22e5ac9f2e7");
            result.Add("bs", "7f019e2340ad94abb65ca02cdc49c36acc20466a6b9deeefe5838f70a39074a926f0c60b28c8d9bd201b2b3ba95a6b1eca036594a49563d78a046834119cce4c");
            result.Add("ca", "8d483630220d8b31df2d4996e25fda996692c36fdd399329431cb7c0c180af7b7cf758f72bfc3b894b53905204ea3e93e086155106fe09d1adb1a509bcf61579");
            result.Add("cak", "a9d3787c19a77d0b014644f96ff38efd123ed1216cdb928a4bcfaeb8c7fbee4709f2f7472c5349ccb0251849d840c6868db6ea216eba2314521a8ef71e32a4bf");
            result.Add("cs", "6d5365285688b1d14d86125c712d30c1d466d52036a7cfd7c412cb87594b22dd90587042605928f704c206f5613f8e9ec3e56d0845955d080f8df934251d014e");
            result.Add("cy", "fcf651a8ca326a488dc3dfa347cf889fa89a54fad42de5a36e6b2e02d822ce3a6e52556c73912fe3fe3bc111be46f546270bd812f4b1d20f448d006bf0364e9c");
            result.Add("da", "88c392958d9084e2decfa2614a53861b5d785461adfb63a69d813505e240a77617473edfbafafaaa2e143d8e974f0193d85628b507918567febcef3c4a435332");
            result.Add("de", "16438036e91d004a4cbd9b1d512e2ace54cf7a9623dfd2ca9c69f382aa4cf53c61461cd6eaf4c4ffb5f24f19e98f1bd1fdef42dbcacc04a49c77384068178949");
            result.Add("dsb", "23a117789fe1b9d84253a389fd68d8fe4d7d47c887442ba67e64ff9d83a96e160e9912a37e40e2a592468c64e133de40471d799b4e05585d3bd2f66325764de3");
            result.Add("el", "286df1d4ae3c7c74c1f27195f048384a29b8fda18ab5e140c24d6780e270a7f54ec0faebf785d767a70cbee1b560ad8a438c04a195d9b65eb4b4af57c0c63ac4");
            result.Add("en-CA", "1ae988f5354b3220b7335ce7ff688b3ff6702c0d6afe8740c4085c7402a490840a961263ad89e8ab78482cbbcf7b5904a2b442197d33390b2fb26bc6feb953f3");
            result.Add("en-GB", "0f7352460abfbc1ba297efec9466f57d1885d45d1b26a35ecbe96cb3bbb7ede648f6fd9f95c47e170d7979e266362b607025c30650b001c80177b966802cb55c");
            result.Add("en-US", "001f5090529bf042321370990e8ce32d60077038b7c84e76109e6111b4dd8d6e0956b7d54d1fda138052ee01d176a83e6ea4933d62528fe33a50e1390122ac62");
            result.Add("eo", "56dd1979b18ec8af4453e1de3e6f1e65305ccf1a888e2b1a5b58fb7fda0d686c589747773df6efe7f61b0d79c7c8e3427dd28f9243507f51e8cd54d252e75527");
            result.Add("es-AR", "ee757b65e23a30c8d592495255b8446719bc27b13e2fa35fa0f194391239c41b90fb6b4b4358aef005415eba59d4140ab662330916f1016946de4cb78d52e1e5");
            result.Add("es-CL", "74a985636d51ba145b29df91c84bd39eebe392a3262f2e44aab261237918f74489d8b1c001b26475abc0d89984451d2e205a9a237f3724f3961dd4d6eca0cc59");
            result.Add("es-ES", "a63eeac271d53b07e3e6cc5685a7f4dd4221ef5a786170a0c004a3e522d875cbc47fcd806835a90f45475face07110ecc3b20eda4df398b19f8d93ab3ca41256");
            result.Add("es-MX", "9ee9fe63d9696e1cb8b939fb8b941074584f6aa9a971b02b66b391c4d5de61b5c4f4d80cb1269488fdad6050001a818a8e4fcdeaff28808df4c09042e614760e");
            result.Add("et", "9a1627cc46263b312e20cca388337c43037915454f51d758d3b657d52de55ce2f3629820c9988e28d4901b588e2e946fce33d2e3d83fd5bb0bfd5935c04bb270");
            result.Add("eu", "d51411397b709303a144001ae3c6c79ca6656d94ba3840cb8c105dd9f72d06b14f858793b73de96e44ad964dd5bf7bed1045fc5e6e8f336681ad62b23d97f81f");
            result.Add("fa", "715900516c2fcd8fc163190e785cf9e9fafb6a3ccf1f6cc4fb942a09c782f0f33a0769d5f4b1e26a75fe73843e8b0059a1c490b680a0ba3680218db7f8773f84");
            result.Add("ff", "f97ae8b707d886b652c062a48765921e2f6180e78c3efd8eb23176cc75ae7ac3a6f4a466d724227d3c428088713162a4f49e588f784ce25961832ccf4b49f408");
            result.Add("fi", "9d0857ed633268d329f38fa46317aa72502de4c446aef32f1ef4ff82083cb50c041e5d72f058509db41b1751679aeb22e99dd885fe65ef1e1eecf3e1df1c2f13");
            result.Add("fr", "725909300e2297d4385ab394e76a4a6abcae59973697c46ddcb8a36ea2186f817652a779996c634cb6ea509955d04f380d2c663b509873467d23b50e81479e53");
            result.Add("fy-NL", "696873e3c3aea0151b0432d4e013c71d763461a6f7c2b6c15d74b555ab58e61a441795a0dc943f26f7c0a55e7a46bda6468bb5cea575eecc79c297c16803c282");
            result.Add("ga-IE", "391b2f9267f02874eea7095218291adad3bab6c7d00b87837534037ef3513c7c9836f72574150d8d165fc95f7ff7f932c9f8fc235a6b400172735498de943751");
            result.Add("gd", "f6d11240d4f4d6b833144504eff51ff6e7832d0f0f579caad84e4c147462b42fc4168a9579bb45d8388eec33d896c3ad619e292a977c657545f13c42e0fe39e3");
            result.Add("gl", "458bba331e134666c42e7781a56e5dd1c0f765daf243a2c928ac9a1d74b5bf9f7cf547eae425e2482d375fd5dffc00ee591b2bcdb2e34e87ef0f8d015c250aa8");
            result.Add("gn", "89cfa992258d41abe2be77833632897533cb2aefcbe622421814d5f9e153bb837201cb5a69481d50690565bd3307ab46fa1f952d27817eb026b8077cfd51692a");
            result.Add("gu-IN", "e5cd9a573e4514ffc672a2c71b3c71429770957fe0db74c315d2fcf82b8ad85f3ed7066a9798a5981cd7c486efe627d415c918b4f1072625d522bf21bbe3a837");
            result.Add("he", "89d10c212d3976a2957ca48cd34bb8f73139ec2b956b21f035190abd7e88bf290d97328decdbed29478b0710d2bdcb871747b8ed0751cd5c581fe7261b4898a0");
            result.Add("hi-IN", "1de21adb11f24cfc5fa3531874453c462ca380723bc2bae3bf9b135f4918c569a9602ac5dad7decad1eaa18a2c709e49423cd44c126fd400aeed4a256eaea166");
            result.Add("hr", "015bedb63f70309548635c421060e09ada259faecebb960f16026dcfd98352d19adaf0e5bbf9914e3405d14d5d029ca4289057ae0dfdc48a96a8c3b34436ac5e");
            result.Add("hsb", "9791407e0de9210a08a7ede6a15f348ebeb11eb2ab2af2f576719b38d64ebe6a3e260e0b8add4f36f27417a460eda3a934e7da65cde37181c2b6c1311d2d5f06");
            result.Add("hu", "9ceb9d496a87fc8da4d69089219eaeba0ac61201ca649df177133d3f0ac1fe596ab10cd2bce43193f7cf84d996c09ac3f962075b235e78b0529725166ac6c46c");
            result.Add("hy-AM", "e354b52c717e57c641c977ff894b5f2d4dd0ce622e55480d9ded10a9deb91de12c953df91d2d48a22be9b296fbef37bbd0c097228a455531acb429e91c9d748b");
            result.Add("ia", "8a1a4d6fa769582210e726fd46be8dd03cf7de9357c6f91f70a89958889e8504ea77dc1df5d17b9b61b734aeffcf747d252551671456ca09f316847a59be8a9d");
            result.Add("id", "d7876a5506e1ea177315f4d6c6375f5af49bdc1c82a0882df1a906a59bc0b06fc41e8c1f577820a09b005e7491f7b9cfb7c5bcc53da92a7f34f2e221bb8052fd");
            result.Add("is", "7adc630eb72cfdc4449ffe9c44b701f4aa3de046095c62efb89d6a5258ba9138c231fd7c85f201dde83306e9874b4027cec7f4b7c0d35b7365c37621181d003d");
            result.Add("it", "2958f62ae58e1cd7debc56016622a3beddf417936a086dbfd7bec57eda03854df4a999be92aa60bd6d74d43ef24c8430aa27294a190e4dd0fb7f5cbe777faf79");
            result.Add("ja", "2068b037c10612e7c5d590818dbe630db6fbffd9afd5c12899cc45f80d811600b4280786dffe3ad3e88d04e4c13442b14c7947ebd262ceef3e3e376b02b435b2");
            result.Add("ka", "c216c02a0909aed9e95c053bf06c88f404df6faaefa38cb3d2824bc8e7ec82909c626b348fc20a1cd52a6139ad8b553f1021a53d8f9e9f42b44a89e490ff868d");
            result.Add("kab", "d59ac3ba25cf9cae3ce685696fc8965c24da24c14beb9171d530bae1f9cc606751ed4d8a347eeac007441d9814363826c6d18521ae0859b6b269dac89f5b379a");
            result.Add("kk", "b6353838c76aafcfeb700782ddd3fad6f44f27f43e17e60609297fff798507f8e32949a9a9ec2881a07b672b0aa7629a31725925351514d86f40f9b137903f05");
            result.Add("km", "e167e47f117c95e16fd20f099a52a604b2136419b62986b1c6409041a01754ddeb6b7c8bd2f9f3982c6405d0323fa1ffadb3fd26590928e11ecefdbaca3a3105");
            result.Add("kn", "c4db7d86bcb1c15524cb6d9b4756647d91a048a525d948fa89b6c17a957e50ede87cd28078731d29da9967ac41122036a468379acb0e65330b72b395c2cb4548");
            result.Add("ko", "b0b19de8bc68374b0e1a9f60ae4760be60544c6bfc2fd27e50e69acb3db1dd4ec6da6de4f75fbb9032741838c060ce0243da008b40f9da70522a7635fe21f25b");
            result.Add("lij", "6fe6f2ad8f54862d4880cff02c0b7787986d69185deb1014cb2c45051017153e13641f790d95af7775c60e475cbb53ae4c3d19132a8421c621502bf62536db38");
            result.Add("lt", "bac21a48b236e5d99c5381464e9986472e6ac09e29ba6bc70538a0d292ad3d5d073c773dc986308eb884a36ddc131f6b567482b899e37a9a9901b50ae34e681e");
            result.Add("lv", "5e79eabad13e51d5bb39b391ef53fcfce0c6cbcae02c40bfce39f5e9c2094c162b13237b534afb139012e8e45009a0c787ebea173486cd6b1e9d226e505d9dd1");
            result.Add("mk", "e05efb93b0797e3be2cafa91f433957b9d039244a4b7a1c997e888b812c1d8dd51d3f79bccb7c0379bab5c6aee45fc11d9d95be3475cfee70dcb5b2f7e070ce2");
            result.Add("mr", "e27b0a405370f7b6a8eec3f7557fb389d1145ded7de39ccf26fa5f1e9a2be4ca41ca1cc7558f4076ff3c104a5f68b86499d52d9118a6ef5cbcbc3e324c3f2727");
            result.Add("ms", "0e504a9c8ceda485b945c4f84619612dfea49e0c9617ea0dfb92dae29c28f3488cd250a275db0c0b44ab518725bfaed279e0c003dd900b17cba3ce537b8a2a11");
            result.Add("my", "3317cc96ac82e91c3353820000316cba5825d6aedce696b4d8d8cbc083f0d07893d47a3f7f7fb67274901224af898de2def8e07ab5e53ab315a549f140444b50");
            result.Add("nb-NO", "c1810b402dbb3e70e1cf732f3ecb7baf0f08b5dc4f2049b2f7e7107e9e2e8e23fe3789c217efb9ad91d18574a91b9762ee87ee5e3a79c9f66048911bf8ab98eb");
            result.Add("ne-NP", "22a670f6c95e7830a4c7b2c4c36f2b8f112f40228593c53f1357c949bf659aa291f9c509a0f8dfde4df74eddf237039122017b3952e70f31e9909e1280424289");
            result.Add("nl", "8fb18073392b27a55be9bac61508e20c88635cf3053f258cd438ae0e75ca8258f9959c7111313ae1c01aa748573fd8efdda864c773db32efbdca2590e001f479");
            result.Add("nn-NO", "a5a31e9d1e8d3c52db04209dee8de7c89274f8f93c10a49dd3ef24f5afac5df1fbce501fd0c63deb4911c8899d46a1c0b0043a045d4c9ac3da955f20e069490f");
            result.Add("oc", "8e11d19b57700c9ae33cd35b05c430a7c88cd37386f565908bb2779b886c454f1ce1d177a492a18d2aa6d18f311a6546f3a40c221e9737c65ac5bec76b11378c");
            result.Add("pa-IN", "4fbf568196008483202b047b1e21d2dc0525b745e2c88184a6e0469419093d3751029fee93c45d441bc0509d21459664c90d205050156c1fc2a5efec73aab3ae");
            result.Add("pl", "11620a84bc970864b01f726e53c59d3de76adcc75c0b231344d27ad7dae8335df1b98d8a76ed246841cad158d1394f1c89d5dea9e9588f32716f579818acc022");
            result.Add("pt-BR", "e873054ca6b4fc552c47dc55c318b4493f4c7655207cec3965cde01ac10650c26bddf657a76b2ddad9c602291add8b0dccc036994193472b1f01752b294632f6");
            result.Add("pt-PT", "cf9d20680a165dec04cad41ab0d2a2d291db95293d8214d9eabf4275efb547bd6aafc6073f2cb97937cfcd718d35699de070d2d02717e5f14a460fadab3140a6");
            result.Add("rm", "1f11338b484728648b910d29025f1a29abe8db1cb73522abf23d188c6882428556a5fec22d1216b66f88f332dde7d2e92921d03e416c3277940203d33ca64822");
            result.Add("ro", "e8af459cfb0da13443edea950b77e164e5259011a0b593d59e6fff8c49d787bee44aad0cbcc6154e4e10c1202abba698eb68784530abcd8769551c57122cd598");
            result.Add("ru", "8ad85c2bebb7272fb93bbdea016bfeedf04b8277c0c748db25af5f8fc656a7e964ebf84155e192ca7e2c5c92b431559512bc8ee4862470eb646946b072e1d771");
            result.Add("si", "cb4115c46e34d3e6a53d2cf70e850dd1079009468c4d2e9ad89745bcbaec64250e3c7318bae20a346e5990c23e4004e2a135e56f9e2a3a5c4c197e88253a5723");
            result.Add("sk", "90da904551a2251a4d7c6ce574f4fe9b76dfdd647155d56a6ca0a970bbd91a155ca61ef3bdb4a22385359af469d51b8dbc6a2052220a948fc741766b35849cd3");
            result.Add("sl", "7493a4d938b88499362c145797018d10162ff49cedbabb142622d5823380a6a450ba112b7dfc4d617f27d877e22749f6b42c65c8fe43232a9e5c1836472d4ac5");
            result.Add("son", "0649a1b5a860ffe7b0b250f7096c0cfd839707c672b65553a9cfa6f9b41437599f287773fc56c2a8f9f603779616b0e665e4e5185570afc932ba24b7eef4f38a");
            result.Add("sq", "b66f51ea113f1ae92cc07b1b453b9a3788b7aaeabb87d9f7129fe39b7a97805eb72f7c11cbc9b601374ab0fa421b2c639a5e47fe65c9bedc83f09732758ed296");
            result.Add("sr", "0f86d06be51829b1d9352de51689c8fffa13744d82e00ec713ffa32db628df608ef596d72cf2dde6e1dd7247b78c2bcba1341e3be20afab1a44ef04970d20e2e");
            result.Add("sv-SE", "4fd00c3cc9b8cf15458bf7e4c7bbec68555fbf3bf8abb19ea7fbfc80daec4d8c9b9cea7e38d4423c8c9eb087740f14797d2ae03a5923f8dfb9518d077a1612e2");
            result.Add("ta", "43cee86b6955aae27ab66f4af675b3eca77beb8071e0ff79fdaf71a00dea246187a91b6eea91910556480d446fe294996f3fc9084f72763f45ff5e35ff7d4c79");
            result.Add("te", "04d30a0a067119f72a4b6e4f0268c9dfe5e27c2679ab2aad7f69fc6f1545bb06e2f868b61e7eb986b2dcf9c560340bcd39d8695a6e980e82e90c9ebd3a6ea0d5");
            result.Add("th", "bb7a36a40703a6fd298d1077cebf505f7c448c94b4968faac3423251734ae3accdd18d661dbd4f2883b5ab186c8f142820b4b2c609b52689c86a9dc005081400");
            result.Add("tl", "b3f4ebbf7adcaceb9d0985177be2bff270ba051037d78397c13abb36f218c0fa2bee98c30b23abfd3f5892cbfbf85b0b92e0f9fef12c1cdeacfae12b311a7a1e");
            result.Add("tr", "28d0d30d28c13c9eb72b7b20dd5c5bfbd30f5500a47ad1a7da47f748160d6a606531c5a9e31c2e11025fecea8a1e8e5d1f56313b206a9b6204a5c35ffe61c4e4");
            result.Add("trs", "43ae91f3177b31b565e49606ae22cc81ee9c39855e57ac82078ec478a58dbe5f703c5b56094d77349d78b4ce346c363c0ae477f800e6333b222b13ebb2eed7e7");
            result.Add("uk", "f71710777a67c2d6be818eea7a440fc706cfc8223687931d364ea0b34c014abccdef521e739f071fcbdbfdf8bb6eb9eb9945760160d8cfab11051c082f086413");
            result.Add("ur", "6f935560bf5f9e48c42d6a2e67520eccd0ae2b7b1620fd72d20134b050ee9da2d5f9094546e120f84edd6afdab3f748bcd8870afa0bc0ccafb40e76ae305ac18");
            result.Add("uz", "20bf69de16b91350057f47ebc117dc1b7a8cb0ea6084bd15e4819dde7a5d770c5b2165dc4ca15896075a8b4ba688d9af2cc51c41c5e7aae10c3ce3c7cad882d6");
            result.Add("vi", "9e56d8898c3b1c248aa117eca2ceac77e68a10cd7fc9ab9b56606214788bb1046f30a36a4a61eefa4c86c8343a35ba26a5246a69b5d2f555284863bf1082bd36");
            result.Add("xh", "1e6a29984f6c881eba17bc95acf20b287ad3a6cd0be356760fa57ec36f9669bcefcec65609400e22ff0d58757c1fc372e1c5ca4949acfe768e55469e07e2d9a2");
            result.Add("zh-CN", "cd6b450ba7c4935538a283183da452a9f2389a5cd7de6903beea79c55391b2bbc1e100acf1f1101bc4a99a8e3b72576281cfabc1be5ed2176d13ec2ec72d5a19");
            result.Add("zh-TW", "ece8be3944e2363a94f2bbb31616926f14ac773c88a05383d59dbf6cbb40caf93f6e7c408e6b8ad58ea31e7b8d777159df8b8f15171c0a9e91487a07578e2da3");

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
            const string knownVersion = "78.3.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox [0-9]{2}\\.[0-9]+(\\.[0-9]+)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox [0-9]{2}\\.[0-9]+(\\.[0-9]+)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
                Regex reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
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
        /// the application cannot be updated while it is running.
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
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
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
