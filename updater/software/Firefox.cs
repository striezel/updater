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
            // https://ftp.mozilla.org/pub/firefox/releases/158.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "511bb3b4aa32bbf1f649859fc4f310adcb18facde55d6a779a832ad9d790ac5850b050fe02af7430123d126a523faba532ec1e01fe995d00d54cf7052b768781" },
                { "af", "b052920b59c716461f282482c8b17fafac20e5ff82d007d2e0c03ca7913a44e1d3faf7fb1b461e1952be07873b0bae02eb75e4e4455a4061056dd8d662c9daec" },
                { "an", "0d6da67c3200ec54d7f8fc73f9eec409678772780a017985e8cd466d38d9477664a2ae4cd148ca2022bd87dd0bace72d88b3011b1937c994d024c0151b9c1563" },
                { "ar", "745ce92779093acc6ae32e3daf9a07ab020670cfa6ab38829ef58b66e19d7b81d9a05a1e00c3dea5123797eb19a99396c0fdffeb0eb2ac4ff1810f831871a218" },
                { "ast", "9d536eb70315e7a18524cae45b8a7e270897727476f17747af113e1495802e7a23fada1467d68c5aca652951d3b29199bc3989ac755f1c9381b6801f01867cd5" },
                { "az", "22a590bbb0cd9025cadc27765f70f50f4bbb1080813042bdee81d66dce4343f682dbd8fe0aa2edc736f98cab79724736779d1e2969903222d220c2989b678085" },
                { "be", "759765f909533b567151b7830cb8fcff652a1ecc697f5392263fdbc0a64c9a53a30ec16d839e0133d403dcacaaa36c6c5280e0a0aeb83dbca6b503e6f7db420c" },
                { "bg", "8883fd4b5be450b27eadca1c2ad1ffb20b244d8434dd05169c37eb80ed7232d76272d7e27ea0a54d063acd0a1da5593ff2c95e71de8c1f3b4909e8680019594a" },
                { "bn", "7fffeff9318c5ffee87fd50ed5739e33693d6a34d2b05bb3ab35d531913048afb6056d3bb6df07d6ef789d7a9a55f98582a0a1e3faa9909422968087c3b33cb4" },
                { "br", "8bca16629dfdcb99f63633b005b3cd8c396cee5bcbc992b9235bd6537c483e4efa24d060b33e4595d99912eb2475dd3ec658a652c2c14f8fd1c42918aae84231" },
                { "bs", "cb19a51b8ec5e6b39c45ad38eedfc5844ecfdef3021ae677944d4fa061ebd552cc8fef61639b49f8409557312ad8baeb6f2b27cc54f3d9b7f6dbb906c2832fae" },
                { "ca", "1892020bae5dd6c40b574192c6c639e4bd0b8aeb2e5f1631680683b1b1e416c9474c3e3d815128586cf2ea90fc948600d84b4b4fea0f7df90b227b6ed5fd6ac5" },
                { "cak", "74b8e6f4784354c09924050f6bdbdaacff3f51edec025654c86739f020c7827dc9cbf7f8bfe87a66a04d73566b8b8f86d498f2f68b1c52ae3a964fd43bbc916f" },
                { "cs", "bf0d2c42ac7fda5491b06de1af755fc8e69e8f4066d8235ba03e074d5bf8eea74072c193a8bb5ae264260f5c472186f6654db083bfe7064c73a15c9ca6481fce" },
                { "cy", "8e975112782416a5e0f0595b72a52c88779c1a112313a72d39a9455135e12055f25231ce8538c05eba03a63e752ba4ac558c46e66d5e544a71cb2f4405766034" },
                { "da", "a8f2450614abd8738df3b031c85a8fdcfc4e1be422dc53cd1125cd6b27bcf1febc700199dc26263960bcf5844df3d0d45f2a16bb806908e853d221d80d0e119e" },
                { "de", "ca1d6dedfc1b998ec3842b7a2e56d20373e38f7f722ea26af12d2a7e32426a727d06f20c5656e97c98be35127174c68555bc7670a434cdd73d6b00ce41ee7acc" },
                { "dsb", "15c0e0f50114fb68c7b1034840fce561faadebdd9f6186635833f14103377efd17d4adbda96b42d6bc2f2d0617a7164187cdbc641436ec3a469a76fc89059f71" },
                { "el", "039a83ab110348ddae67ba45bf2a57fe9e79e79be26883d5e0bdf7c1594298d07114940fcd75179fe3e21be7759abed19ed9672a4f84c59556d680fa1346076f" },
                { "en-CA", "eddd884ce248640c681565ce055ebd13acdc26fc2994bd6fd959bffe08d0ec5bf7ee2a5600e8c48e7ddc5774649d8e127d738f65b2f79373f94036e249022783" },
                { "en-GB", "ed3bffaa5f873f6b1d727bd260d462fc56244633f51ccd7f265df51b25490bbbae126dcfcef87fd2af9b8d0b721ab88e5f7575555516b33a907cb4c84f5459b7" },
                { "en-US", "898de8b7766def369c1e38bec3c6f12b45e39ab1e9c6cadb56ab0a157fea834b7dbb24bbda28151217e4205684f3d99eb492b372f88c9b72679f55669f526269" },
                { "eo", "c4862c8f94bb7717ffa41aa4fb34909de59796ef252aa925e6819af7c7751bd254d65db87d02e0c264c60c5bb8dbd25c9ea44f6275ad7c8cb0210c8df98a8a0f" },
                { "es-AR", "1227c3d7b90f28cedc79872c98eaf08d5717aee137c47d400f5e3df7e4d5419b1ae2a6b31031a4875aeafc077bfb264df47dfd95ef798719a86e20acf61621dc" },
                { "es-CL", "6f0e45145bb0c5ee6a6d30d6099dbe6a44cb0164784666ae7fffae02011f33841c62883dfb0e03957fbfc665955805a7f27ee4a5159bb9004a3a4348ae9f5399" },
                { "es-ES", "349ce124a331e0b341c7a414602e4f62704417f326d41883e28123fa8674b7f8213749566c73cd532e8c9d850584ae60169c4bb2ce53857e6de000be1082f8c2" },
                { "es-MX", "0ed43af078f34b5e069123fe281bd09fcb0734ada64a692e53c1557e7e7e79a114e23a79781f67ca9c372a98921f110d535b708beae3482c015ed4d8047a2922" },
                { "et", "b456337e52d065436620ff6f46dbd97ed3fc7fe9bb4d177554aa0a1e287bc34b933c1e411d8c71bf4e1bdeb8af2e9185984b55888b70e3d89a3ba14416651dde" },
                { "eu", "8e4e110df01daa653d07508f69e66d567d7e6296a858fc79443ed0c8b4509bb88a17f61746ae86d96939024463c00e442b81cd8863834c09f0e456a59aff8667" },
                { "fa", "5bbeb0db58087e1a5d47c155ed535dbb6e9537a2851a50f96d357f7d7fafd075758e034373c27b9b79294303993bb8fea9671969c4c45893d7b906aee6686479" },
                { "ff", "f1fcba019d28bd9eb3e57368c24ad1a96daac637cd8ef35ec58c16321ba98d01651ac9b7671b854409f855a12c594b9576956ab7661cea0eff48487d8978eef0" },
                { "fi", "ba560c62c7cee0657d2ce59cc648b9a975bd52a7a11ac65bef04e0f640022ff286a39b3334ee2452f2d86752614cb6345266814e0034ea4ff064ff47805478f8" },
                { "fr", "7d658d0396fb8f2fdd9a028d95ea0f2a3938db324fce6bbb254bfe910e78fca420e99f710d0a672d407d4b9c71a0f1cb118846af2031c6a17f3a276498d81836" },
                { "fur", "3e305356098b9d281933470611c67af838053afa42de6fcb9abeb0c9f9c6fd758226ff673e18c991a17692c5588d98354c528f1cca483a067d4eda5237966428" },
                { "fy-NL", "8725f2e633985e226adf1473143ecbb32f9295e82b59ff8e7e517a519be4026d2b86cce5c5ebed4a85f7e72aed1309b8f9f2d30d453c52d8c979b521fed01852" },
                { "ga-IE", "0a41f3a51ded34a763ab72c897fd047b36cddbee8d6460b4ca5f2d460f573e0cf850036022bf2d36f3ed4f7d66a30bd2cfb0cf1eba73ea211cbebfd551f41100" },
                { "gd", "efa239c79a65c481ae09768fbfc839a660877ead3332819c20c4cf289037d052af1bddabcc5a0abf7d9f37bdc83f6aac035b2f6cb130f683b7ba13fc6e9db9b1" },
                { "gl", "5144d5408e63eb6fefe4896eafbbd5ab45236a05c7538f1e266924da145aca6200014b16eb3d9cc602b00df531bb27b18f81720e81f0cb83eb847769fcee95f2" },
                { "gn", "f586aa67f5e6fcce47d404f096589cf7812e8cf77b83d0cae483794c3e2ae8431240555986f3f90efe7c3c112a7e5a674ba029e8715065f08c97e39f9b11800a" },
                { "gu-IN", "6234e2b9b2dd80c088c8a6a315df09acb33eba98c1d38ba966436afec7d5e363bc3eacf83f374a7cfede99a8cf34357c8d3a00bc6933d5020291183a9f483a92" },
                { "he", "308dd520f44c825ee2765919498fd022fe2946b3a4b0505facade56fb95ad205a650ea78c356cd78c8c90fc0dc79324cac9592928e33b7ef111d91d2c0d9f0af" },
                { "hi-IN", "b95f9a9342d661412994750175d26419493ab9d14e78eb38fac64a736bbdf405b9003a8e8c241f942c885aa4559a9a544e8cbf21774f4d5c4f72c9a08d9d8bda" },
                { "hr", "26d901b078231e5b9835b8655c17a1cf42adf53613691dd5196242f763072952c99e6ff8d10ea211e9759c83b6e6068b44a906d9ae6b6f2d5bb7a3cb2a8d28dd" },
                { "hsb", "380cffacc1d23f312dd108e5c4a883a48b5f7f02a7bfefc959e796ec389e9ad21d4fefc0b79ab37371944446f0601d1ebf424e71a00218775a97e511ad632f2a" },
                { "hu", "7cd939743ed6fa54beca751854415458774b2eef1e5bcb664df4f1a02709b0489f483b06353ea6c400758f38093fd9c27f446f6a6247a6ad7e87593739f198e9" },
                { "hy-AM", "0cf51079f869a25966ac98289a1437a9024a0160b4fe74266d2d1b71e616ea61de110b3afadcea04a6f43440e8f43c01c245a0dc1a0b4264623f575e210b9593" },
                { "ia", "185aff2f4e1dabc4c34af9ded866667b7710ca1d153bccffe153d1b0d01492a9a6b0f0f8558bab26b9c812a8d56aac1a71832777bc3c6ce328ce9ecd3d77e2b5" },
                { "id", "24c026c35cff489707dedcf502271e8645fa4de7c85bac6d4730a0b02e6600d62338e9c65c85c746a8ff9b0efc0c6ba02e2cca88f317171cb60ae853a54fa70d" },
                { "is", "d42075f5427e906b601e40cadd333d4f5d8b0183419799d848da64ce8e8b16c0f627325a2390c6bb5a7eb606b37010002c85a4a5724136562a6f91e3afd67b6a" },
                { "it", "7bcd31d59a8119c0dbf9cdc6da913a913de16eec6b10d8641cecc45812f940424d50c5cdc5819291309332dd772edf53aa13ac8612094a441f792255a2fa3d08" },
                { "ja", "b259ed835356261274b7e4660a602736ac12ff2aa586b4749c08e5e50d8aa2475f6547bb6e2f916344963213b6ee6aaef37ba0810e6b6ee15bfa2028c183fa87" },
                { "ka", "05697b39dc562073ac5ae386750a9f3b8fc1ae83f7b2c63656d44ea9c680d8839f194b80e061e718ab49d94843b5ed17f88f9fc95d392e1c514a32589f4162c9" },
                { "kab", "9af995cd68e686eaf295289ccce038ba3da00b00481a198e561a7ce689aa0cf478fdd0b904ea2ad6b0732df8c103d3fd3dbae3b67e9c69a5a7013d4554327811" },
                { "kk", "b3eecbcb7751c621541f468d2624426689f793ab950232d32e06d6346b5e10ca38a25e95b4c06c91734bd4972a83ae7af2b3370c2c50c29161d068e61396bad5" },
                { "km", "b2fb6a96868d5aa652df526972b97e9bede962a7334859825a62c8528521af728c4e4219de173e081dfb1c904b00cc816db72a1b344470e755edbfe8e4d02bd4" },
                { "kn", "402cd516a0b49f99f96293ddbfff52d8c421e72060214d956df32a6d70fa24fafe9236ac21b76095cd01805b190160b59838e02f3c5c6b92b5e625ceb4e08043" },
                { "ko", "3d6428b8f4aa1a68952ee465afde1b5ccddf90cfb612a36c895449e13fd16949de2c22b4c1635cb75e67bf934c4f2e60cb7ed0c9b8f5ba111793aa734578860a" },
                { "lij", "077545e0846efb31f350c4badfaf5c72669fe6a50ac7c35f0e966319344c3f76421aa338cfe3fada2a63ac5fcc41a6b671c75ff927f4c867f785eb470f06a53f" },
                { "lt", "bf3c5299d46b4bb28f34f62b6df187315216417e8ea5cd38c5368d13a248fef15a986097f8fa6f198cb454396133c3420a29c1b9616619490d59ec71ccfb50df" },
                { "lv", "b7e20f0b047e1d8a0a7fe61d967fa521548610d1f1377b096b9ea339b6d366f851d2cf6fda2303e75ec6bee8df5f3e59deb54844db535b8eff6530ce44149a4e" },
                { "mk", "d374cde8355a0c097afb7924262ea53cf1a135fcf129e3cd71bd7af4048b0b00f230ddb4422a4963af8519add402d2acedbb1f25fe6dddcba1a451c3aaea1f8d" },
                { "mr", "a532468f601e41cfb2c21f3d80712026aca1fe7a56ff860442a717cb3c139ef6c76b68fb0fcd29e1b87aba64420ee6dd30860c3c2f916af2c7126ab864b6419a" },
                { "ms", "fa6dfe67a43fe16ad6a0fb0f8f68ba91ebe8881bedb48f232f6126fafaf169e0b1dfbb31172279dce0a2767c03f299ffd716cad1173b7b25fd56433d9887e4a1" },
                { "my", "efac23a826f42ca8a0a814dc53969213b0c7db0e8ad5761b69ddea6988a7cef6a07ee69a3c09006cca923cad03fff44b7a46e07333dc0205ecbda82c2915ebf0" },
                { "nb-NO", "23eb0ff493553e99f48fc079b8cc7ab102af0f691d6ceb33729ff20e96684f5f943180776b828d3c97c250d8644afdb8381242d7b948e818fd6583f4d10c5068" },
                { "ne-NP", "4dd82dfe6d9807bc002f8b8477a97546da5ef1d698f361fafe295fcfd3eed4b9fe820e4cfb03002992f47fa5d7289123b2ceaf2760264e7a872b68ef29683cc9" },
                { "nl", "a0c0ac01bb2d2a84e25d6839e42f491fbb80dceaff6a170c1f0df61eec445185f79b4ec9ef430e6e77ea2f97b743cc5aa9618e2d00de37671db0c2ff7ed2881a" },
                { "nn-NO", "a9fa492bc78d26e4e1c425ea8adb4bda73b405dac94b8bbdfb8798468645dbee1964590fb1774f1592692e02af9957406c20ebefb56cfe69396e5eb3f54182a2" },
                { "oc", "510386ecf92e50b113b0236ae37b854c16c8920db98503a6c18aebdb269161e6dca47a27183af41892ccd4f62ded28186f6dff257970dc4868d0f232778e7d35" },
                { "pa-IN", "93036b3c9ac9996559eaba5d533e631eb0cc74bf19b9293cb898daa51b91d70b18a0c70b80aff9a6475acba83205bbe577254b1399fd669669f5069c2375a146" },
                { "pl", "b2197c38fffbf54da894716ab42df78727a39747e80868d974fa29b108e318eae4f6a5f86f28319d84ef4031115564f07832616999cdeb75454153293616a85b" },
                { "pt-BR", "cdd712826fcd3ee55a5a26960d0d9ebc457a5843f602fa6ce09ce962bfdeb06d26adadedd3c3c5e7756a2a022f35c409b8ee1b5bf9a71b302eb1601cdbe9eda9" },
                { "pt-PT", "83de8446765f0c4d4a424294216e13f3d221b0a7e759ad499c290f7e6d8f7746f46c9ddbde7ffa1e01b21bdbfa0d2a1420b41892f39b26ac7e33503b8d34e0c9" },
                { "rm", "19c86e039619f96ae3c4122f77cff116c1b6afaa2a19ab174098666ec09f16826bd141a805c35e1aeec276c282adb722c5ea74dbb03fba8839e02866b4f4fb05" },
                { "ro", "cf8c316056293ce513ee17fdd0204ea46d66cfe87011725ab9bb209c77525de082b211dc9c4dee304a0e4d03c28fabb3f652e3eeb853f975134daac8cca99b0a" },
                { "ru", "2fd8adcfb94fad5dce32b083899899185a91632ceadd9ade10e272152d6b19935220d647e61cbff479f1bed4973c44d969f63c0e506b4d90ae7cba0800f64057" },
                { "sat", "cfb3cca9a493249e01b040c0f79b0b321ce4ab5c3fa26894d6742e6401d4b6efaf0c214e89e1cbb276f823ba6795a63aeb070b05969b57905fc7024167f11fcc" },
                { "sc", "95752267fbd33800df2583c132f9da3647b9501132277d0e1b0cbdf9147480e29a708dac509b3b79a1fffcd303548ee3dfa8e7b6f85348555814fe61643a59cb" },
                { "sco", "047d183a453af20ded320c82cbe57abb869c5301f27900188a1ca971442c5d63f4d6515fd3cd087f9f1b02d4f9c715be8b236832bca1729393144332f81eca62" },
                { "si", "5a751be806bb74944d30a1b9a5ec7a1c08901c7effa385a4271e7d81993cb3ab2efb193344dd2b8cf23be6a1189722820b32de15393e4d99cc984ae6b43711c2" },
                { "sk", "db61fb050a8782b1c8927cb7671ed5941a39b4e7324f56141c0f4b3547ec3bad2593cd08f4d68dac2049b94c86a9154a9f9dfa5bff68ef59f05a10f364d732fa" },
                { "skr", "90d3ee3fe48003ea929c72b36677c74ca6b5084c97987db681efbbc5f9cace41ffdfdeccc84dc9bcbaf2914119ae6d7903ecb3d2a4f84d93e5b3bcc35cbcbb55" },
                { "sl", "122be02c4e0ec1dd9dbfd44c8eba88ad16e3a4310c73d3fc06016b79ec97ec8a8d5e15a9b1dba58c8b4d48e9db025c2d39a27b47db007b7b2e7813e2118f2c3d" },
                { "son", "bd0e1f54f4756e00b887c585cddf6a4570c8cac780faf9a99184c5458f6d0d10833da332164b8fbce1b8fd10c3a53441d1c5706a1682d3e30de72801bbd56432" },
                { "sq", "39de151f11eb92594216a71a2838ef25ba1a4269319ba032eaf401a819b553f05f40e4fc4c40502cf42d60c0a70df06b18622d5f46b7c33b2fa03e5af9c4fb39" },
                { "sr", "4bd4bef1069e00d05ce4833e936598b054b328f111baa5bc441f4cdcaa8a44b4c28f5330495717237350cb5bef7ce30949c41c86c0ca2bf89fa8142bc28d6dc6" },
                { "sv-SE", "56db9c52490323e0ad21bb62a873f2209e1c574602b67a51f49f86dbe1108c4a01755b26004a193c8853736c1026f56dfe9614168b200a938d8c51755d6aa233" },
                { "szl", "7996c1c724cf1e48e0680784f1b64cd49fbbb7bc0c96e5559b5edf19d0d1fd541647c79ada6b19c9a9c8239df60d49d58429d72fbb2128b70660c58d4d43652c" },
                { "ta", "ba3b8114518cc3dda939495d5795cfc4b0f640b29aff924beb5345e5422dd7bdd7c27e2e88ce7a6b69974f2c92524871d2afbb0530f7c4e64430c2cbf3e62b1e" },
                { "te", "d4c1da0cad04ad8be505987f0c0631cd9a4c2254d61937ddcfe988b78260e75bfc0cefd9c366bb6b416c44fb23572b0d6af40d8587f88784d6e107141fd29791" },
                { "tg", "b14713e1377bb5d1bcac994f2c8875b0bd5a1f3645ab08a7edb3ccd068d7a4df70e0c4f59f16eb39ac674b4ba7c70149e3876e2a92dce9a75b7be6164286825d" },
                { "th", "d94aded423dfdb0f3ca1d50088ffce28a9f57e7abe14b069beedf14538391f279b7b07e8f2e205f8176ee98af936401ac05fe8f78da5b68d4194e16eb095098a" },
                { "tl", "beeab3f87809cbc05f01e67b4dcf1bb4638b9a1ca64dcdf73d095460bcdb27c4dc5c33526322b6552bd5a841f080c1808a1b292547525b4311c82c76583483e7" },
                { "tr", "de4061f8e7aada9a02f4f7f2b01376e9e439f2dfb4bbd01c132c4955a57efcdf142b7babb3d001aefd2120fabdd76a2784572f11ac48abae49b4928ac9f3082c" },
                { "trs", "e9463fbb048617d831277dac82b68b1c6894cd33fcbdd0cae50e43a451b3ffe6bd82cf7109f0b7ffc0925c2c2d9fb3fd353035dbd5795a13039e020ae0fc088a" },
                { "uk", "f4f1206093f5114ce9971c068c8065f299ef980ccdf35f2b70fe2812562e5a7c6133092add7ccbb1d7141fb5825a272a1ecf9909f8c6db153bdc8c14c1e95f44" },
                { "ur", "b185e6c05ee4594389ce8d7874e4c7ee71b6701eec3efd2790779b6617fef23fa4516b2bbe90aa84d5eb17f8d45a4849ee5b15861dd4ba6dde2ae8856ac5f7b2" },
                { "uz", "144645d3f5fd97935facf09e6aaad877d8f13dce7280324b8b1962e553d91b4af6bdd5e87e741e779d8bb2eadfe1edc11fc7b47f6c441b133a0569dcbc7ce599" },
                { "vi", "999be3362d56b041abe889811045ea61b87ea9ffbc5a60596068d4ed03635123cff0b0fc94c91640a770343bd863041af68546d377f02c3c5b5b77176b5314b2" },
                { "xh", "f98a6e4df2f4dc85a78d7e0534196f9540e0e37dfb3dcde2274fb4537d7a0f0bac603e96fea3271579b89541bd2d00b63d8b72fcb2c9009639a116d95f91ef54" },
                { "zh-CN", "a08d531081568b5835a90a50e452fa8d5c1234b967be2a850660752be99d6e6f62cf7b6355886d5ce26f7cc55892593c0f6733dd14aea3fbc254e84311791b4c" },
                { "zh-TW", "5e1212c91dda3a847caf2dfbe413de017d560a299384bc202da70d68b86b711d3cf4ab898b38851bf03bf805b392d0a10da0413ff051e0a5f00c1bfb4aa3330b" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/158.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "c5853c31a966a3e73910e942b0ddc154115a5108c224f979b4d1674ed894f02170ed1ac2f1b61ce1beaa5e4f72e07f2195e2f57b39ae81ce96fb64f854b78fc6" },
                { "af", "cefe537ee45ca940d0fcb3afd80f5ba5b2592bf88f6cd372fabd8bc7b010e5808bc112ca69beb3ce35c71a0c2e39471d8f219c215f6ab81fcc62d02cfd4bb7f0" },
                { "an", "4a14eacd510db46a1af9d49e2dc3e89d0499e5f5b2979b39f5fe53e1b2820c45b8caad315e304f1c2427491a2864b0b0a433118c361392de280743dacdc54de9" },
                { "ar", "45866c2dd86648dc630c316d00353265d1a369ab7e1c8f9e9bb715aac8a7e090bf9212613bd5f314596fa76c2ef4d84e4d46a018057995af431c0892b267c80a" },
                { "ast", "1399cffdc76a480cbbec4c6250f8cf01288009bcb85a41da15fffeabf88b37ea3bb1861dc677c0c99c05ac49438ccf293645f11b7f615cb495c0e6280c87dcc3" },
                { "az", "ae23d50dd53884b6749cebab12d346cc08421cfb25772f9a774e99e25944a394c8a2d9320ace5b1f15f1f87cdf165d16bfddc6b364988c2ff78ae349185aea51" },
                { "be", "c8c355396b131aa2d4c72aa5796b002be4424cf2fd16b5e5e9ff600083895e16df63b2d3ae9ba5ca48be7275591c4d46e665cd898c8d5ccc620b32d8cb629003" },
                { "bg", "6b87cae3f53c36ff8ed47a48e18eb3be1fef947b352174c988e470a8fde858d6cc11d4e2d3d26738b09dfcd1e228b004bbf514ece5226d9b45b0b188f97104a6" },
                { "bn", "a05325b0460ed78f56a45485198f65954067faf215c5594b08835625bc7a1a1409c606adb4cad280f9ffe513edba490724d6ff6043c28716d6c1467278be75a7" },
                { "br", "4a6dacefba52c74dcdf2361bc022963da1845bd01d0485e67f02487e355142777b95d85c1fd56191099fda5c718651960da568901b115fa998f9412fe933acab" },
                { "bs", "57e9b7a962c16984e75fa2959479bb92d59ce637c90c2b661d0c0ddf5a60c1bf839eacb73d5fecc405ab5e4b132f8a0d909129d565b039cfa84130edb8402930" },
                { "ca", "1fe5c4d16db975dc68aa222cf55f8693fb4069dcc4377f84d6b5ca073723d5227ae899cab57dcb9fc6395da794c486f687e496f0ce433a7b7ed213a202d5f8e6" },
                { "cak", "836de879217be80c345ba84035570bdda150442a14485ba9920d3de503a70d2f566f4142ca829c3d8e5b77e85680b7909359fb63189828211351f9a9a90e4d64" },
                { "cs", "bb18990678aaa3173db5d61caaafcb407c449d5697d48f1795303fda4289fbb423c203b801addc28cfb237e8012eb31f0f311140ebc39cf67602597c80b72f80" },
                { "cy", "9aa45256ad6b45c425cadb80363267db05c2a2d00bbc9318ac3d6e4e6a50b2dd483acc20fbf0f4fe519695c7ba797685dcc7d2279fae482bef0bc3f2541416e3" },
                { "da", "7389ba463bf3b9a5405d1ca346f6fd8c2a5baecdc01cf905252853c42d5962100b5274b65df53cdf303727faa5dfbfb49989f13e89a54b828ad6d07bcf420ab3" },
                { "de", "fd20f79805edbe9bfe3c8ed0a1ff2d76494501ec420a82c199c2415d439fc93e20b807b09b80d35449baee01849e25feb988b12a1927a9a22cc659c0612c6a8d" },
                { "dsb", "58267d1609c355967f0f8e8ef447ece46357520140c6642a913de43525b48dbf1c5eaaffb7190d9bb367ba90122efa75f6b41aec56cffb84304fecd757fe1309" },
                { "el", "3364e1eaf0d258d6865846a037f69d4fc5bfc1b9469859cc573db38c27323f9f595fdaebd60b469a1c81a459386fd2a7fa443d7e2116e9a35fa313b865aefb83" },
                { "en-CA", "8446dc558253127f2b1fe9897d3f6ce353bdb0a4a6eba9d53bd1c22a0c4d9710b15e6fe251b127e79d41d2e57de851f409ad55f18e97de42bb9eb99a0ef465b7" },
                { "en-GB", "7a35480cd2145a18b3004e82f1858df9193e743ac0ab6af3ec52e8133d0882dfb3a40d7cffc8ddd195d562d3c2b97c20f7c2f3215d420041ef8854504cf5e6f5" },
                { "en-US", "45480d848c055b807b1dff3551d5787b8481bf710e0ad5760d42d69dc8a8cc200e5a1eb3e41be2386c4ab521971433815babcf0c4b9d4c35322783ba54a41b75" },
                { "eo", "d1fa99d821e4dd7bad6491490bcbf1cc4b8a11254fa690596778fbb809ea58145d9a1c7d9a59436e88937d9842ffd30a916d5d529694f8a5b8f6201a6e1e2585" },
                { "es-AR", "2e173fa32ebed6f7537caa3c5ed28c2cd34628552d275f468e3490b9ad96e640c55558728519fb150d7b748d453e7cacf15135ea1c76cc81a6912fb196eb4ef8" },
                { "es-CL", "94c6a6a8c0121c247c18fda1bb78c062c0e98c05152d08986e399a5ae476778e152e39d592ea5776b6e902c647acfa1b0f903227256d3aea768e114399b5c802" },
                { "es-ES", "0f6df57b3c80a09b1b0fb22b1edc85a6ebf71d4caf011c710a7762c3a25c2e5867bdb29ec2ad351d99adb8931d31539f6ae6992a7fc7bee756a4e48162ecd3e3" },
                { "es-MX", "f0edabead6c0df26feb5a8ecb6901fcea039f0c29514c7e5629ff80ba1cf90abe51338f0cf7d3286c9959d5e5c9dac0957ce8b6129fdef05787c1a74ce43f6a5" },
                { "et", "6c602a8db79a282050cb32fceeb7b710c0b3a90e0abb5f07864f40f39dd2dee65fc2971ffd57e1d6bcaee3ee769da0e2b9f6c0a5a7d736f20aafe17f50f6d5e8" },
                { "eu", "3c10670c856102f3704901389869dfcdb29696070a238822c0177bee57e24ae0f4a085421fd21639b799ff1310e0597d0b3b7ec5c998265e8db185f06f122437" },
                { "fa", "8b64f8aec3f47e6887ef2b15770b5219fbe3ae2c53bd60b4c562e1b1bcaf092a5d8ecf4999bc20e9731793a9c4f362a4f6fac73c2801b51f60f52f65eb6397fd" },
                { "ff", "96742f6b73cdb34ce5f098a3d2417da97f8ec6c6a425cca424667c367e57129deb2abcc340ceae99abb1d85a13ca89b58359b4052b0c9bfe1e24dd3f123b2175" },
                { "fi", "4f331a82759b32b5605cf254bdaa2b40b2f7d118614e1a34befa1df8bd691088696a93c7bb2edd88866ddca81335e68e7e55e792f68b610bd1c252292ce6e59b" },
                { "fr", "dd6f42163ba02d0bdd4396d74dd761b1dcb55d1952e7b6beeb5ac542b02d5a2fee95d67dbdc84363808f5696c3dd9c3802c6bf78073c7c43e1a167b521caad35" },
                { "fur", "3d98811cdcb7dab545b160fa6ea61f99184f5fadda4c7f4f7c75d438433ef19a58ff0296ee2c60884764b9f4059fadee4b3243d4dbe2f784d6ddd23ef291c547" },
                { "fy-NL", "322b5d75cf7c7e48c891cbf1fbcaa88e7193eab222aa854b0c0d81cb205dbd2079e9ab1df5a8e80dd9f0cf8d5ddbfb56247e2497cff71168f61606397aefc19b" },
                { "ga-IE", "54abb13e7ca6a94c3b86eb2d07451dd6b250094dc686e55d1aa772631e760947666533d70b9ecdf0c5211a571cc00ed60cb31410bed861aa25963e1d3e40cd38" },
                { "gd", "66badd7a9a26a0d0f05c2c1ab21ac546fd7f7d9128187a09cce08a63bd3062a97d9bd584a401ed6d60277a8ee2e5532f152de52d738f9c38856481c0bd94723f" },
                { "gl", "753dc4e9754c682a5b24685f801fc9f0b96ac33464ee47d1150f0b4229ab0a5b7760fd80c9707aea772efa244e9fc048ee482fbe035b3ae8aa728c38ee453c6f" },
                { "gn", "a990bd7f382b3af8800363bfc38fb4566742506a50c450f699e7af1bcdca54d0150de130366de4acd09b4bf25618c728a89d6f13ca1190a116a3d799237867a5" },
                { "gu-IN", "3a46cb3502bcfe979d3ca889e26a90415fca4c6a1726ea7046a118043b8c72c305217651f5831123ac5d9b6ae0fbda622397c7811e42cc849cb1e135f702fe73" },
                { "he", "7d4e5b5e1e9898e5079efddd74203fd515e8781bc946f12094028d8675559d4664e769629f252de23477e01463bc06216f2704a5e07dfe77d91306afcd4f9be7" },
                { "hi-IN", "5ae8e49abc6c60f755424fce09ae7a5bde173210ba2c8d2c91862c57c25de3b757fc85a66b7d89ab4bce7e6e2f925da7d4265302962c08a8de7eccd39fa95661" },
                { "hr", "8e1a165a2be0f0d19b320690a075536b572fa013e5026c1ebf31a044f4ff2b80047478d44f78aa46afcbfeb2658ff0173ec83681e5e553ce8bd81de14a038aaa" },
                { "hsb", "1466f8078a8a318b4ec8ebcdd75718a93feb7e3aef79286b502b0c129424ff975e5f5a52eae14772b394640a2ea9e292cc33e1427530907bb42d2f2b3a96dc91" },
                { "hu", "7da280bf40d5de8c716ad0e6b0748f634311e199ef39467d48ecaf9a8284eebd90a585d3b3f6f6bf4b40f8e265649b04b074e6e27202648a3dc2ff084f8e5db3" },
                { "hy-AM", "09874405e6464b8ec20ca989d23e215d11f6ce3b96219a46e3a4bf3daf1003d3916b935bc1a83868eaa76fbab7554a5928bb6ea20fd74b0a052908e3579a9a45" },
                { "ia", "0af1d5ad6b7fc44c1810b20a1f615a14968f3bce6827548ad5fa8c097fb4874fd3372f94f8784d27de1d1df6619999e6aeb4143dc52d9d9f0a7b8641779bfaf7" },
                { "id", "f486017a4e0f0d490d13fa1055200beb12798de1a1a3e4f8474d1f7673e98c0b2bca289a6042d90587d7fbf4611c4b2cce0985ae2f8617e7ce8cf6aa6d433315" },
                { "is", "e6f2d5bbb5dd963c7e3a63c38f3e379424336b442017734a221661209e59fe591378328c19fcab669fa3dca1ddbd2c92f44c1b4929b3707a509474707a4c9c8b" },
                { "it", "86d0aa1a4f99ceb31515d6cd04d5f9e44c87b72a188ec41a4bc34185c517367c9547321b2b659d43821b3eb4a6f9b6ac9c366e5dfd4404602783cb91c713106d" },
                { "ja", "efa2a7c11867b185895eddd39889f30a48f949c7679f2c29a11c3c48786009f1668c38544bfbca5fe6e2132470da4a3b478cbf607840c78ae9f63ea41ce525e5" },
                { "ka", "1af4198cbb501095733a3f0178cb6948357ab3e9e05c9e7df5d7d99ef042c0c5c3a1485e2304b26ec6f1be61d2535b7e735ec46eaee534d4fbdd8d7430692ffb" },
                { "kab", "33d2ce28f53c7ee04556ddf35557229e9fbfd90e96d239a6b6deeb7ccab390497dadd065ae5ba52eb82edb6ad2a173e02fa09dafcb16a70ed271831b76e6b580" },
                { "kk", "a71c523475572e765c3ae78ccc85299c960cbaec68b5e194a3df29a6cb0d15eac8d2156a89b82fff184b2fa61719f65c00edb02f327b5bb3040eab22e02a3006" },
                { "km", "ff3f25a9f2bff6e60d96ab24f3754aedb7b9f92fbc48bbdccc39ee08595c67ab5ec9a7eeb5edcbbf330c205ea21a76a24597a672155d66677fe4eedf3e4ec64c" },
                { "kn", "bb69f0a863dedcf687758be246d381c369df1e5def61663547ec8cc0ac66b472198db68a09eedf13bae4f049cf6362bbcd14f97248a58af1d3fe6c74c8f4103a" },
                { "ko", "2ff370ba692b1602b7c2dda96488f57f3d9fbb0215876e20b7431656bc6404d905878b2d2d9e20fb9aab6a0ec5eda95ff946e171cecc57a27c98c318cd20eb65" },
                { "lij", "d624c7d53145f257bb79addf8613f82b4b8f6814a3505a89334ed1a527bb3e80194bd6acb6745061b437db827a48065e7a6945b954267348e3e921c8ce3a13d4" },
                { "lt", "497709233cd19f4ab27f6b7bfb88025ec1880c46a4725b8e6709ed27b16d21269f59ee3bf3fdf5c9e846ef686f2a286ba9a12a1838d0ef6ec080c7ebca6b11b1" },
                { "lv", "13615988bc0855b1e1924caa1ca4a7b49dac0ec8f276d4007a9d8518057c21634ed92235d8e90481e6550ab72cd80c72fc9d30fb972f133374996ebb6bedd195" },
                { "mk", "15ad95e932aa28311cf2db270c5536321ab9e3cf5fbd2f790c5afd29c1ac3515a9ebce18a21da2f6d1dcf2d21db95dc4b8d4aae94d4063b5ebe0d302f6737433" },
                { "mr", "19a9ee91c620c7c0fa96f8d2c3e8eae855c4b8acc6ee6053589f6e007c8c77fe22f8d041111e25aae13cb1c1aa3f90db470b8f13b0b6930d047c319728fbb7b5" },
                { "ms", "b44b63b91b4d5a9c28490a391e1c20e6b025b805809e8a7c90e3cc622788365212d7902393771d09464b8004ee17ac8b3edb0cb318c6b862745be2645a095733" },
                { "my", "a18cf6d5bcfcd9e720bfae493ca6f786655a707d58ab3f8bbb091383fb2c181b9cc4d8deac5bd8add2634378a70d652f905bb2ffa2f29e6751223481e2aa1823" },
                { "nb-NO", "0a32e4b093625ac68db1993b0063acefb4c4890f545ef9d6a2f762898d53dc4de6581f15db730b574c875a46fe517a61f42c9cf7b88558390b3d338726a943cb" },
                { "ne-NP", "5f0e7716b54cdbeef8704ac5a3a93d10524d8f4a59a078c254e50cdb12088f9f67a7c84eb6fe32f5206e7fd9654c5785659eb8130c01d89f9ea3d1cd04bcd44a" },
                { "nl", "c87f05b3c8c3b28df3420e8b6b6ae8177a74a977c195b1ef672aff2e26222abd3041dc353f5f0895babdde567c724afc2c309ab15032c1c440e23c8bf3b05851" },
                { "nn-NO", "80e20b8c8793aa21c199a0595575976a1146334b8488a9606a2d56a718d11a46b6cb6a34fc24dfcf507f6eb99f60dc040364651013afd2272cfe87912bdcdc66" },
                { "oc", "67c229bd4307366b65ffa5c0b04c1f99bbef3ba5d99e27e1ef329785bc68043ecef54c09f97a23d23a07a6fde0cee1d5e5bba8438ddd15a14c62b94ff3177266" },
                { "pa-IN", "c4b7ee47e8d9fac6ee45dcf3985b3bc75b960d869a600175151f5bffc67b8a6e850bb43471d68b364b652cda47f777151f17934a2628065ae2e7ace621aaf96c" },
                { "pl", "e69c886fa19b9c403aa0668c1319143aadfcb1fad2fb71c5853244eb8d9214e52451d7e918fad5ec90386c07f1c2e9ee522c3d6d4574d6fd8b678dcb7c20a14c" },
                { "pt-BR", "a86111e72ec979e7f1f6a9460bcad2584843e25bec00c5e2d346cacae456e94ab3ab156f0b1fb08e3440aee4c2372f480b62ec9cc8487f8bb521bbb9fb33fa23" },
                { "pt-PT", "249615c9a1597c85c7d8a6c6480b0fefe63a2668daaee85b0dc3572070d8eafa9da3b53c3ae581ee8130a724498529b2b8f5261694ecb6d3789d957701f7dac7" },
                { "rm", "7722cf0c0ba45008ad21f1863999f8087defd190f2c8388fa426c452504b766ffe1505164537b14b43811ef74845d6ce496f0765bcbacf849c1584c1897263a5" },
                { "ro", "2e82b35e9b572cbebe8d0a6a2117827651eccbb24bee70002e069d05196df53b524e95ef608ab25dc61d589aed272dd755a28dd2ba3ed97e4e1b030db01dbb84" },
                { "ru", "72103ef0db6fb1c426ff9da663833d239883470488570f3af51d6ac5953523e7d87bee13edd312830dd5030c8a53cc750c0329ea891e1cf1338f64525ac564f2" },
                { "sat", "34d52e6a105aff4e0951386ac7e5d64d8bf83d14b0f747055e7ed001544559614917e597e7042ec8ed17608b04e34ee00c4740cab860af751bd2f8999ca382e4" },
                { "sc", "40a03f89531fb136bff619c133c6fdcd21b21e65830265c0db64ae36693af7dbb7ef1202b93671662dcc1e19919ce21405001d7e5faab7b423c9b5b7e587e7cc" },
                { "sco", "2f1a76d877f79a475a1ec5b5b091393f74c0215011c81e4870aa806bb6eb6f8bf073d75fb987be321d2742dccdaee6f2c7d8d368c0c947008b9c728d682d3358" },
                { "si", "7560b0779d125f7573202ff25d018f62ae2dec2dbb4f64f1680f8e7d3d97a46daedb176f788371922b578b7d2fe44e61904e8bd339cde67e1f3de1a310e0ed3a" },
                { "sk", "5049ccd7d9ac0c3f0da1cd921ad73b221eedb34672c079467f48b9239b6f85e2f84096dd8da18212db383380baac1c9818f9917b3eaadde9675e66abcd0224c5" },
                { "skr", "1fc9c976f03ed3a0c29172da9d58967283efd1333eb2e10c135ee0d86174817070c440b60adbb80a37aee4ff9ad10008b998534443884f8d66604b346dbd26e8" },
                { "sl", "73f63b73ba9c08ca7ab24301ebeb5cbe4522a050189c436c34132b6463f0e07da8aa89228ea9ac6fc44ee84acd7ec287ad445ab50cc9c7118ac8fc1749dd7bd8" },
                { "son", "5ebb27bee5bb4e2ba64897556773a93bf3109b3219e88dc6f8607df21ef37ec9e63c651a974908f9ea8d7f6e10f7c5c61341e62e148c8cb77a324bbba9ff94b8" },
                { "sq", "dfa5588c63d51daed12bfd13d521c09be82b6649277a8991096a3b1c96f0070a240a729cfd0b6f5bbe6383541a31971cb3fbabe66adf0fcb73c4cc2f3366ef67" },
                { "sr", "dd0023424567ce6ae42fcf81a651b60905a4017812743e641466a35364d46d7291c324267f7c2d3ccb389f06ada1f6fcc56461ff023355d148a44b65b44bdd1e" },
                { "sv-SE", "0ae187d8140e0588b88ebf8ea8ead70e5e0ff6b402916cdb7d7d35100ed857389d00411b2df382b98999b7c3b7ca08168c6f8f2570818ef3f2ccca5387e50ce1" },
                { "szl", "e069ccfe26530c3ded2b7fa8f6d02bce07635baa59aa854390abe18a5a67b4f1001911be737b7c9265ffe98160eacfc6c3b138a659a0e047423989eea8a43319" },
                { "ta", "ca4b53097d3b72b2f2bc3cba920a45e8ac863a5268ffc172e01ab024be92b5f8d9d6040ccfd3008f3deafb50a5ebb6021a76be1620081996a03299e01c0e26c1" },
                { "te", "0209672507878570eb4be205300f5c3f9142bb7f44c7e6725199e6ec2d0e99eceda560c0270180a9ecf2173bae2ef059829c4e0777689aafc38d88ecadc61d70" },
                { "tg", "d6b23b7cc60859b40eed2669c0e82dee64da614e9d498230f475e6b1dc97389c9c7da6dd4a9af96ce46e5882ded4a18feaa9cbd29842685be7850f1b49b596ab" },
                { "th", "c263354c60ba5ee630537d7c165b5317da1df45fc19f63befccba37ed24900ce926e5540864dcecb49fbb5968086e0474caf730e4b8ab2fd107363291c721c82" },
                { "tl", "881c5a3ce6e4eaf5d5416ed071b90965f7226c486da894afe1daf27cb5fa757c06bcf564dc56ce8a16f6d2871e53a5620eff51e947768d01ff9735674e61415a" },
                { "tr", "0e76240ebf6de0147804eed604b2c0d4eb1cfe5483f0ae258b1476d240fec8ea3c8c91503b78d0d1141f128aecfd2578afea92d626755ae19f2ba0232dceb45e" },
                { "trs", "fb8b85437dffc2bba3fed72320ba2b0dc5453b251051cc504cd94be77b3da4f82d59fb19cae01da170d4cb50daa6cc356decef58bdad7947dcc0e9ad5e0a61e3" },
                { "uk", "41d5410a6ab79bcf2d2361077b1a690cad6cdad5e5f08eecfb1190fcdef76ff1268683dcb2ba343d24aff39977502153de7dda50ef81f420ad2c40d7df587586" },
                { "ur", "62f04930ca541c18cd2db74d9d71fba23da2baba3a08b3b6836a50be7ff02e9687d961ad960098d94b1ee448e9d1193bff9b1f3c8e413fefab033591bf727a48" },
                { "uz", "02a70aa5b4d0a7e254003215c6f70075e4feaabdbfeba815c4a4a5bcee92f0190db2c14b787c70651df72a5080dadcd5813d569595e31d0d7fdf0d17a6648198" },
                { "vi", "5408b2624a6e5543d6be9258d3b69a616fe4e65b141e943d39842a283a0899ffa6a66c0d44d09ae06ed0aebe5ea2b83743baf629b6d14941679fafcbea3e345e" },
                { "xh", "cc40a6326f27161ae831606e98e67475ec9ac0307748ba170b7b54981d6417e809fc4357b0b754a590d234f5156739d687fc70d8c3da90d4b3de552f1e068889" },
                { "zh-CN", "bcaa68c9b4a60b6f0aba90fb6022ffe6dc24bfa1d5d4eb1a9b63ee0430f62b525052d02674744180795992e32a14e83fa0ea2a9f2ba8db4f9f99e8e6e7ed3c22" },
                { "zh-TW", "55fae8f2a923754a36097f67eaac02dd553230a4ded41711a57539d02c5ed7119a2490936038f609fe7ac7a70fabb88c9b28a28e1b3922e5f2975a6f537b5067" }
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
            const string knownVersion = "158.0";
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
