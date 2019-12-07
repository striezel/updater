/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019  Dirk Stolle

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
        private const string publisherX509 = "E=\"release+certificates@mozilla.com\", CN=Mozilla Corporation, OU=Release Engineering, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


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
            // https://ftp.mozilla.org/pub/firefox/releases/68.3.0esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "072328f48de8a0e501df506f332b628decd6e0484fb1e8502157aa898b25bf5cc91ecc3facea83e64b076b66ef886a7350b6db7b30ec03f659df15153412da41");
            result.Add("af", "a53e188ee322662d7f550c5b776d574dc457478e36b122c8c141a3b693adff10495594f4e6922cdd9f2220ba3531582150219286d06225f7739906de306742f5");
            result.Add("an", "27e04bfe7c311fdf986d3247fc6ad82ae0bc848e53d858b580c0e95350eca707ed6a08a9311441ba1b2fc9ff7430dbbdadf83dac1ddf92ea5de0a4fad1840734");
            result.Add("ar", "45556c99f9b21974d03c64a71d0bccd600533cc11661c68099c0d5db80cd7e715d10904783de76396a36feafbfaf9336a9eaaedf16162ecb037c2bce5ed8ea6a");
            result.Add("ast", "7bd7830b4c9dc3ffa867dd66d233ad7138efc8559e93584df7b7269c2995bf79a6b3b876ce7b6383796a79906dfe39bd1826f5e6aaba67ab2865e9456ae15f3c");
            result.Add("az", "9bc20fd49366c41670f5bec6621c17bf72ab88c68835735fbadb6f9da04a49a0fadc0f0f20dd6f33b3980ed0e8a6a172384e054c3e6c21b0071f91f602b2496c");
            result.Add("be", "37d2d2598adb000639aacacd98f0922760341b3402fe2b66bc862b7ca8c91c92b776e37e9356c0b6582fe5efd3689b0d14025e94d4fae72a109f019717bfd2ab");
            result.Add("bg", "b9a42832395e980b541fb201a88f06bba0765f84b81e3ce305bb58bb399c512f1b9bdf479583ea5d77ec8586526a47ce586cca7e2158171d36d523b8cf8baba9");
            result.Add("bn", "a1e95a07063ce6d280d7a83358634eddcfbc99a0f18ea5b2b9da3907b5520d7c40d599b11828fcf3a59f8021b2887c5b1228544d3884e79c8e1a2d02f9ec5803");
            result.Add("br", "b4ca35f9ae88c6c56900421317433fe99f0a764621e2f36c7a5c4efc2a8b2e01ce2b0db8dbfcb760de3a03169452bbdb4c6431dbfc17020f399a889d2b6f664e");
            result.Add("bs", "4a43a9c32186f5ffac1fca9a12d216fb2094db69d3d6add65deb5a19bf5742ae0dec76693f8e3b02976cc31f0ef3a64e8b6fa3462614f3c47aad7ceac3e1be09");
            result.Add("ca", "de06c75c7e2e36a4594ddf5efac166a8bb9edfcc4acb8b2025d14401ea5334ea0c486cc9a76b528c958dd4eff64dbf90f4ddc52f9dc982dcff94c3900832ee74");
            result.Add("cak", "257b438064e9a0b13aaf66d09719dd252c61a1203423398099f420b41931f5d0af09c822c9bd5851bdfe2aa170a11328cebb89fd8e4f2715b77fcd2f56e65372");
            result.Add("cs", "4c04b6633bec1e7928dc99b810ba8362486773283ce5b2fb1270e57a8e749ec5fa0b621d94aa3b27cb832f0b4f1239d2e8c42a4e9f67656dc4318dcedab91542");
            result.Add("cy", "95dbda7504b62c32e3726f13b37f0eab8689336934abbe9e018717301450d6be9d22a82bcd7a911db0ad84e3a60218a94b53cd0810ac4c03f75b37eee56973d2");
            result.Add("da", "016cf57ae888b8a7828664e98eb4c6ac1c0f4d162fcf71d7a9940dc774178f12ffba9ca400178e1ae60af88e2696c5a50868c5d89aeb92e9b60fceb0005f0746");
            result.Add("de", "42e5633b8fc578dec4dd17c8d4697f6120b131cdf6298be6e17796e13bbb23fd959dea32c4cdef68aa1df4269844ad3cae6a184f91eaa8a8fdb3cfcec6c9aefd");
            result.Add("dsb", "64da3806209a1b1899348582e1c799aba72d99a827d0b495db8c37eb128b19ba0f3f6ac3d40b6af9fdce7381b4bd0d22d971d4f2a8ee74fe5c2fe7dc07a77cfa");
            result.Add("el", "bc7909cd3d502c47cd5fdac4df62049de6d08a384a3258996325853571298fb794afbe52654fa4ca63a1b84b726d8bee4b11627ed3a10f8b7d133cb8cc9e3e28");
            result.Add("en-CA", "43abe3dba9a1067c70ba0329639414811c0acb62c2b82811f75b176d99dd97293eb5bdb356e63b9ee6d5021eaa04833605086ba83b50ebbe0e3335c3bf2e0c7f");
            result.Add("en-GB", "c72955bd573209d7faf9e9bce21c4d6bcb0d8d36dafe02905e278ce7dd06fbd210b550c0cacccaa101fdfcb21d3611fa186918155e2480e40ac3d6c56061dea5");
            result.Add("en-US", "9ca2b37b0fce739096dc738be3d73e4950de8f4563a683e28d2dc85fff1cc8ebec621d1580c8e3f0c354bb93eecdd33b9aaf82f07366c27069d71add32a9c8f7");
            result.Add("eo", "372dbc948c3e2f4810ee392c978e289448d96ec7fc12e9817a7a8bc2a9186cfd57032ee538fbeb74ef43d31d7a7bf38fc32db7d7dcae093d20a18f2384165547");
            result.Add("es-AR", "bc11afe2c89a5703115da30b91c581edf00b0a0ae42fdd6a4411146d9965fad324cf9dd7cbf66a43ac4255389d860257e38f4f4090ee83ba722ac6d1a6b34fda");
            result.Add("es-CL", "6757bdd3daed701e2f55ab7b65e7925dc872a3ae2d83e49d7d4901011c32baceb91c985a76810328be8a67a6610e3a750b54041362add031bf150ab329354705");
            result.Add("es-ES", "e7d7b63d69e084e9334237d4ad59f6807295d0f93b52678396f29a697b348193ff412562961aa17273f5ad6d4a2af8982776b432c5a950a270c7db3259d3a228");
            result.Add("es-MX", "84ea71926f9a480c0b28846935f974da8794cbe3320135033668645227e84dec67b97d21ea4c487f8fe18b08b75a39fe21ac025e332522ccd37a6cdc41b4d180");
            result.Add("et", "6c98eb81ba5a670577ee34d304be5b007b186782befbf1cabbee5465c2cdd68cea20f22b3e9e725bfd2ba4a3686de267a6a6a2834f457c4fab8dcd5e2683c9ad");
            result.Add("eu", "c2223bdcdd70cd12fde7a380a091e91c2d64c5bf54823eee622ced4ef46fb474c1d79c43471bd58740e99eaa1a80892e6b67a34c9ffee8f0410902ff072e28cb");
            result.Add("fa", "6fdfcdcca857b974c340abca12d07231446a0253446b7c473b63546e89e6429a8f5bd1d1a83636af981d28c8c1f29bcecd107d5f939961224d63de6e23ca3a81");
            result.Add("ff", "34d24d6f733f62634ac4833c42d51adeaef91f135072ef7e822d106f58deaf5dfb1d8fc74abb33befece18291cb8c515bd0cc45e2a96d3626a95192b2a98a429");
            result.Add("fi", "026f91fe9f7ca0497cb9d9a6fed5e5f1b7b8233f908dc6dd40bd8db6ef50b7adf99da1fd3d1f357bb02d95384084762d7865180eae67302430466e7e095de16e");
            result.Add("fr", "6f97e18cc8280ced096535f4072c43883f4962d47975a918f47d9c7650855031a919f5cb7b9c801404db45fdd036e55132b16fd5fa1ac51efb1cd4c183eadd8e");
            result.Add("fy-NL", "ad215b8aac19f1a32ddfe6296d4458d226c5b023f574a4c6fcf551705658eae44d7d1a8b3eee0b96b0eb3c49b1eb89488b285a7495da116e46dec2601f5ee4ab");
            result.Add("ga-IE", "6d79368e18e6127c33c6b1003aaadb6b62dc4aa679224d9e7d2be140ce1180403fb7f61086a07a19c9fe8b6ceeb37049e2e7b9eb029fc905dc16edfcb0cb04a2");
            result.Add("gd", "453baad3195b8c496292333f3727a7105a748ab3f1499a832868bb9d79a88c816bc86bd73ad954f2f07b9e4d18cdf4d5210b8496ff8e7ace7cba79a31fe1fb1f");
            result.Add("gl", "4e9a8b884c867e7d07ab445252b9083020b91deacb35d71627a9602a2b6d0053531c43de54586b0da6a8bf758185076b6d76a3f8b52c76a944f2eb1c6997d1a4");
            result.Add("gn", "d51de3f6afe3b874fe1cb826fbab426fb0bd1a7ed46406bde69abe613e62954387793c3e6d28178c6431fff3ff4a388b5a46d9f791bbfe6e942d189901ada067");
            result.Add("gu-IN", "63e1ab6248318f91b13b15bb4d6a6f6aa9facdaccf1d47bbf9e8273cf4b66dc0605f8324480237d14e1e860507134aa5c2f6e5f44473b7275ca30ba863e96d5b");
            result.Add("he", "a231371f539a552bc2081be5e0a4b801f6754b909349c3ebce04470297d02cb193e3f2f77467f51e0b94f829e97717fec1063b2004e49e9f4e1f0335e7c79592");
            result.Add("hi-IN", "6c04338d1b7f86053273c94a917a15e319af2d4dcd760193ab2ed0171a3c44791a92dd2810e8eb935542680433411febec14412c5834d114638af0514c4f6d40");
            result.Add("hr", "0df3af8dfdec9733fc55a1d7c9f41ee4221cc2390c794bfe00f652c79a02c65315263a53e3c6f70e0594863c01416e26929a0059a667c20d5f87d344cd4a42d9");
            result.Add("hsb", "b0ef4bde021c60717de73769128df250204dd138c1deb3bf0be03395e717aea04e2762728b4a8d72935ec2cf75ed8ea651636ca04fa8baab544fe05121d5a20b");
            result.Add("hu", "da8435409946ab15635f7e81a20af8a72c8198a76d4d90cce33ce6e262dc854f3a236f3772942d5d67d5e3d61ba2a81fc7706df95d768f39cb3b64604f853a27");
            result.Add("hy-AM", "0ded7c6ad1d78a25e06c99ba82f4da1bfbbfc5fa4c14ace847bfb9e70939ada6ff67c7b551ea95a910c30fd3bcd8203c1163970f53318c59433a00350cd9835a");
            result.Add("ia", "fb8d7bd9d0f166ac12fd2f633be7b783c7e08c60e9038a6e48b9a75f14f36dd61bc6b1fd463ba1236022d5d96932f75ab2e4d24c6806dbada818e89b56c774fd");
            result.Add("id", "2da0b33ef65e90234fafec78b9540ffdb06b229af8a2da9d4fd6aa816a6be9c20615ec50a0d69d30491510f2903a054156c07bdf7582a377450d98fb846764c8");
            result.Add("is", "20983ae2aa0b4a9e9eb8a5c3147fa47dbaf293cafab46cacf39ae81a099ecf96c7b4fe9048db47dd2ae032708ac4b60718f2671037c1847eb2f6180206387a5d");
            result.Add("it", "3f2218d47850ef02cdd4449589d87f893e9c3da82d48183ec595600ea4654f64605ca3467963fb29392d7e08f72f0d415a0b38a0d33114031c438eb4007feb64");
            result.Add("ja", "3adfb7a14f734c98a58562925a7c0d0f0d60027902d6ea71a2b71b426ff93f5c90dbc5210c41f789ae0eb4c8d1cedd0da29eec1ecdec2d103437558883dba8dd");
            result.Add("ka", "9300ed14906a50b28157fafdaf72b6c1a92cf7b47ba9fee13758411c3d7bbae0ae769d23ceb47df5e0dd8f75c41a990562f405050f0d4ed99d421951330502fb");
            result.Add("kab", "26fffcc62379fa692dc4355a00daeb15dc33fd3a522efd5e22f7b74faacea0e76a2bb02b0c0b08224725bc98cf927f97b62c9fbc91c7287fa4524de107febb10");
            result.Add("kk", "eff68850c25859c20e1e8ab85620bf2eb8a641dafae0edd2fd3762b70dff55477a280880c916353fe04d241240e18f0f02618b220f2a044f3280a010589d35c1");
            result.Add("km", "8b48d77032e8352f56c78b829957ff502bc5d07f33c49419fd45717c1be581aa234b712c39c14066e6af645b76a0e5ebe3a6760a6ceebfe3e18013b3f9256929");
            result.Add("kn", "64449477248be328a3306a41308abcafdba188bad91dc3e42086395dd7c7a6477921f9df576b50d203f4f6a8da3586f9408f97430804843dd16026cf7d2c1c06");
            result.Add("ko", "246f691d75a11fef9bd1bcb27390121da3ce0aa884ade180c3ab903b440a6d5e411b1bfd067d1ce4aa70d8c0eb50fa6a82d43f33d330f8c7306ddc4d42df6c95");
            result.Add("lij", "0952ddc69e0c27011265eeac6d45213884659f1057a085c85d24b8afdeea26161288a38f61f192de7e2fdf3989411e7295e76155f2b1ca97e97cbf02b16fee7f");
            result.Add("lt", "7034fbd205166a6ae49bb3753bc4da1f55aaad3e109a9417ab959d5a4ed16159c084d05c8ec53ee30ce762d377823f729869ffaa2bccca98e74385f27cd274e7");
            result.Add("lv", "985444719b314ebdb515f31e1b545988796557f3c18a82227c1be8c865245cdd3545e37c89730068c041f387b591a27f87a2d2ba6b98a6cc8e3d1d76456ce950");
            result.Add("mk", "553e8bcb071efb9b4c24dda17f2b1ca21c39f8e298d7d41a4a1a7e241dae4773491e91e15d29f52207fe71172e252dd9a379435eadb629ce834af942de8d7362");
            result.Add("mr", "edf19b6b038af11781b4c70ee197ce57892db1d0e2a0c97aca1887e0a34abbf43556303e095f4db69eee3c4fb336b6f87b722e4c717d89dca880bc08bae46bcd");
            result.Add("ms", "8ea9f5b3d8271c328572bb374ce35a4946cfd71f0bc52b3508f1766b28ba973719fdc81717c534d6ee5d3984380b4fb6da09f307a6b2d97236fd8be055769a52");
            result.Add("my", "3047b15243e2a4f30a3c393fc720fb4dd78e1406ce04c2ce6dd2d4fc6bfb3ffb3e5cee5ec03906ac4a68cd028b2f1a6d46b3674a00554edd3389f7e601896d2a");
            result.Add("nb-NO", "c2d0e3a25a987380b21c690e745039cca934028e2948f7c0e9cdf15f1bf2b277054774b8833107a5ae3b210a9ec2dbf95b3440174648f07564bf2b19f5d40478");
            result.Add("ne-NP", "c9be8beb4ce836670348a1b4a25723002f8c3930f7a5ead1b07e5e970d6b6b66ebbb96a4f26a1ebf97e1991c5d78e8cf2be12c8ab430845974651faaf268e1d9");
            result.Add("nl", "fdb2a84ab96b303e2199020b121b3ddecb8fed124238846eb51eda8a531f07ba62d005379fd69063cab4f0d8992c61ed1047d5c06be8e086d544113d6acd5ba5");
            result.Add("nn-NO", "175187640028fc216760b670d9abb73e5ef8e5edd344425ee1c8f1571ea8f3c357189768254f0ae812fd30a33966bf4f12d7b21001c205ebd1a5d75066bac69b");
            result.Add("oc", "c949a1c92a3a9a06d6f81af66e5995462f53b1e49b9bb1631f2bb3f1c1837fd1bac56892189187b9948b02f6f003c0878664c28da2b3c46492ac454e66ad6754");
            result.Add("pa-IN", "af7efa1d07b05155dabfeea36b9777d855b8a8b431561f64298e34d4a391bcd7402ba56a5747478c6a9fe25227c6ada30e12d002067bf17beaf08552d2daef2e");
            result.Add("pl", "7f7c2f86e64c669a129b8c1f15230f320bdca2db8248e6c3e7e45c260d73301851f42ffbf926fb03f367257ab5ec09a6cb944b76dada946b6ff88777a5dec20c");
            result.Add("pt-BR", "c871a0fc30ad996dfe000952b766de2806e6c490ed10339a257772ae676210c179d3631cc401b3c00075212d39b4a42f35514034002236bf71e09f7cc363a3ca");
            result.Add("pt-PT", "9adcb298cee858766d0b6d2e779ae8a3bc0b7567249205223f1f6f0edf6e2ef505642f7b0f56e63697bf0f6b6848e371d59b596180436a2413c8f8f2c2a42d0c");
            result.Add("rm", "ad52aa81e08573d9dcf303ef47a3efd382bb89a5b59e9e0adde0d98e242e69fbc79f3c6e1aae4887d490895b83757fc1f34fae4510b816b8b31b06d70de436d7");
            result.Add("ro", "153dd20623d8b9c10232e865244ecdd27a3db13f5b2ca51aa50fa6ca5f57e900d725bc4ba08d4b19f341070ab4557cf60b6bb559dbeaedfdcf7effe443201688");
            result.Add("ru", "2cb6694835cb24702021556438d112b64224f8b6399563b98baf7d0a7406a3df0c1d3d1c4a2a024ca81eab6ca6754bc571025bafe2763fece6beefd3a75c6db1");
            result.Add("si", "2baee7be7868d77520114bed66fe0f4fa5bd1e906433d45b1502c872111638441e6541cc62753fe59cadc2ab2c012032774bc04d58c990507943ad366024ace3");
            result.Add("sk", "675b1a1f9f5c3b739a6850c8985c6f992d277ee02f32a8828f1c77e48dc07d0cc35b44e69b2820be645e3918cb32e6e0fd28f4afbac6bbd1c82449e9f5a4872e");
            result.Add("sl", "c67192a5412f290f5a3e8fdf3e77eef4973775a4c03ae047e403c80ea9e22e6af3fe11d1d35509747ef75037e5618047a3fbfe0553b6b8c2f655e0727f7603bf");
            result.Add("son", "50e296ea981a6d6d4441c054d52df63be26565dc72b5a96e6e90b6274e2a925a691edb27bf86f4f96ec344d34fcedb8e5d62a810bd5babafa718366a5d6b4801");
            result.Add("sq", "1ff089a3e06d3ef165d1519fc6406b02c725f1611aee7963b04710e88f0a2afd7987f0cd7199efe95da7ad17412442df19f96bd88ee1d46daf2802baaea9d25a");
            result.Add("sr", "915ab669250c4dfea3b02d888055feebc1b89296374520d9615e3a947344fb9835c6ed41a9d6e9d1189661abed0da5fb2c5cb6c1bc00288b42788407dc46a1d6");
            result.Add("sv-SE", "cc0a2d096f3495bfc534fefa8996bef5a3006a705a45cd42d3812fa3448cdadcd67a4f4427e1254054da7ed7842562fd4fa6e599ba1da05aa7205dd3e2a4df59");
            result.Add("ta", "da6aa4635ce0d1003b61e21123a249c29f6da043fc8cd17e94fdb6eb8a0faf7f223e004f0d3e91c23214c06b1202ee59136ccbdc2bf889c5cbce6ae8d4c50395");
            result.Add("te", "b29b213b0b89e4e140c9756130b73082dd1dcaf12d6b04c40d1ba25a82db4aedd8b4d85493c273a0f0f62d29d0e21349b8bf98ecc456c2ef3288132987bf6408");
            result.Add("th", "2b4e404c68e1d14797171274bc19e07b541d63250ed61993f5f9aac2aa8f75b75d1250bcde449e3905b3881ef0f2b5330374583bba6946922b769d33050e8f6e");
            result.Add("tr", "6ec59b6a593e11adeecc8d0dd36872f36690a2df40d3caf8f0f96cd63de8b9b4e5ce9e612f314ff003182a1e3e3205ba4746e4e70e940904899f95c792999a66");
            result.Add("uk", "e6fab2ff08e8c6384aa1ea6a21bd9e7d0896c0bf839a6efc69b06b3e3d4c434993b54887f142f229a5f7feefa5100da361d40ff3b68960e05c800f1bf76d5d0c");
            result.Add("ur", "07df697bdbe0333fc34d6e495b5de9acf51d40d6e04106d059a0d002f8980c13411072b4ea99384f25d530a72097e7abb5f66f41405bb5aaf4d5ca122e2862fc");
            result.Add("uz", "fa94e48232d7b22bbb59973c4112c11a957ea453afeebc6648725f8afa0c9451ab584a49970e33e5d817f158d769e7122995e8c4f4ed9f81fcc7ebebc041ccfa");
            result.Add("vi", "310733d454aaee7a27dcadd58aa492b7233b2c6829f2aea69606e9af56b117daa9868b9cd45e812288d2d8378a8fb70db166b4fd924f24d9e2f6d11eeed106d6");
            result.Add("xh", "21c8dd7c7f442667ec397cc6b6f6023f4ff30e38003ead306dccb2d94bc4de8c23a94f8d9383e25f8f096761d356f57441c5207bfd350423ffa2458a15874969");
            result.Add("zh-CN", "bc3a0c41d33266ae88b78fa45cc9d4c7b50bf2e53983403098b416b8f87c46c29c72ae9642cd71af367417d2b3477ac8d2b56110184bc35deee7e786537b05ed");
            result.Add("zh-TW", "d88a04835dac592c3d4c48a272bda056900b653fa67d1ca7a472bff45260066cc0246ad9e60f8bb100da6de8aa054bb9c27e673686033217398032991620f7b2");

            return result;
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/68.3.0esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "5d0e8c4877a89a2af8c9dad1ff02e64b8f0ac979d31862e8acb89abcb6d41c4f10ebb5b3b0efe94fa71c4516e2f5e1975cc9186c86a4373992080c0cd7c0999e");
            result.Add("af", "5c0a95e7f39dc9ff93c62f9e1f4656dc5f5b29dc92d205d54d3e7bda24b6afdbfb45566853c44f65e94394321313994481e76ac6dc08e062051fda5aa3a8298b");
            result.Add("an", "d947cdfb3d96457cfb6f4c5ccea14cf569e8c3d36cc1fb02178f7d0f32c25030ec737e861288eb409e7e7530b469deed69f6960c1c80e23070ac526ad84adac9");
            result.Add("ar", "7988d5bb53f71b144bb97e2d122dc503ef3314c3d792c9058b27677c86c6952f5bd82526aff2881aaf222e4a1d173cc149a0bd7c0ef5879f72f9b92e75cdcd61");
            result.Add("ast", "7a2b502a0bafc3010bc6ab847d23ad8c06b19e0abe83c6b8fa8e8b8c8db0b9335fe08ee4a17cb9da1a641c3d65fbe96c5bd6b6ef777b74b79f1090e893858352");
            result.Add("az", "27d6c878d12d5d46bacc6b90cf7476b74dbe578f194ed7cb777d68beec9f688adc5fa82e448652ad239e23e90d9fbb06ecc610462e40747fb74bdd1a03e2c50c");
            result.Add("be", "d637a9e209537d5e4f79b21358fe029c19885ff9471aa9379a16ead4ca0ded944dfd6ea852de5443ad60c0e67a3cc11af3d725e781f771060f94d1186c834ea5");
            result.Add("bg", "510cf8e82283b39f153b0a30bcbbbf82de199c3919e4a7b5b32c1182bd1a0a9af38a6ff32dbbcb048fc8ec6975f78d922f37f763a5dfec1c37341ff7ca30e1a1");
            result.Add("bn", "267a5efcca73885d44d611cb6726251fe3c8d451bc47ce49fd35a06d943057b1099aa8fcb35af31515ede28558bd781df6ea8cd5d4d09a95511af1fdca86a143");
            result.Add("br", "f153f91435935a6fd99cbaae1b434ed154f667420f23736fefb98343061ac1e71b8d830f687e5785c37007a35fd7d8abbf94c996597ab837e22f728ae165991b");
            result.Add("bs", "efc1dc7e0de727f91843e50e21c348929cdf0f64575e40e0a45eff418a7401cf6eb28e7c02a5d7a9233d7460180a7c1ed386ee4b17fd41d5a59e3e69d63b48a7");
            result.Add("ca", "fa81e6831f1f756e06e05448ef6b384a2996b4f9e5db69b376af93e10b6d8be80f36290d6c5d349481cdc02e395467d6f284551cb7340812138500cad3754d8c");
            result.Add("cak", "36f78b2360972a036657919b940bc9ec88135c4eb8953dfcb76508a081b9cd620c3d4805213bfd31cd222f8c60c4a1a5baa841437430d98120d969ec43bd2d9b");
            result.Add("cs", "3d9e4bb05c01f2c6534b3e3594915014f1ad83e7a6eabc3dea4bcd948d656e44f36c36898b468b26d63d241cfdd22c1d9b714e6cdd4a2c0cbf425175e85baf49");
            result.Add("cy", "b6a8f80016d5ee7dcb1e7f84d46883127dad20c3d8b1129991e91f4ef34e2ab016891f9e6f93ad0afe6edd0493a550b9a0e5cd02d884e144c144c4aa8ae18353");
            result.Add("da", "bbdafa4afbe9a91473e5381f9af451747ce4faa531cdb7433fca53be607e7f1a6ca446f5309a035b91eb8cddcc7e6ab74d8cad8c27fff04c2b959b02cd666a4b");
            result.Add("de", "16283afaf8f5c48591cdedadec5a1d2b0992ea4daab49d4ec94cce22b42c6817e5e0550be2fc54f65cf9e4df77e8d97428384bc35b76c02fe8fa50fee6069ff0");
            result.Add("dsb", "5f498bf5a928ede8787bbcabc4bf3b0eb5e2a701b87dc15507a662655955ff38bd4fcf0d682476142ad5e36f7eacf8c33320346d396549248b86be7141ae9d7a");
            result.Add("el", "863d11eb5d3f2b2cb28e691d87bba32ba2e952d7001562dfd736bd971a44fe3dd986d97d0058dec9e022e3df5722e1e285bc495cf8ad11600b0900b31683c721");
            result.Add("en-CA", "6630fb61137500589ad640e6b4cbf7f9c6a1db07ba3ff4c5f9a7ed9469c6ef2e849233ca0f72da43bcc3b23e42524869362e6876e3bc3ce573200e98dd5fb616");
            result.Add("en-GB", "c2a2b1c03eae91f471c771d06266dda46fa408ec059f90a508e0e41e7dad0be9b62d6e21c579d4274c3c7ffd17369aaa6c2966a033a26e27ff4c37727a442c08");
            result.Add("en-US", "e955ad82c5b6700395faec226b1b89adfe06fe795f02cef2f4273efe3eef5cdf25cf5763e00ad3b37a10c33e634a61253d00cd162e1a1bcb5baa4e9d38aa4dc4");
            result.Add("eo", "2eb571349a004d5817d603d67ecf2ec9976c0af0ae0b25bccfe59bddb56961db949afac4ab75a6d0ac46316ee303c86b5b6de91f3d2f5d0f725675346ee3bbc2");
            result.Add("es-AR", "7406ae83f31711a4188b29fa0d4e7bba3cf55a5e981c44c6769a52ec6ae6087428d6032a2d527ddad8d791d4939e12fc60456dc16c17f78ebc8cdf7d5a0411a1");
            result.Add("es-CL", "ecb0e5eddf57a6563572ff0f9e89a202df2e1fe3678b6cd1526a16df6a7310bf4dcd1b101b9cf4f37405cf4d4b00b7e10cff4eb9422d027ab76598562c7df6b2");
            result.Add("es-ES", "454883e0a34eb9afe6ab2f9dfacf337a6f9381ecff4c57be0719ea59f14e910b92d3a6f55e6ce50cec4970d4458b45df0e350c5da16f73032ca50f9d140edd48");
            result.Add("es-MX", "a9b2d75da04733f658782fca4e78911a0564452ef276f9d914690e6655fdcc0f0895268a35288d8ffc0678d07badc5e777a9e88cd5892829b54690b46ce6cf68");
            result.Add("et", "aa56a2c1620c5c641c7fee87108cdb57f925d585ac94ab9d20a4c4e3892f1d72716115ecc63fc6714d2050af3d0a7e1d321260eb472b8708529698554b726e3d");
            result.Add("eu", "bfe91951a9d02c1260da5ec5957a6a96a84f11891470adc3161ee852e4ea3152d551b25ddcfe88139d7c144a3a942ea5f26eaabc23310c7675422268cf814232");
            result.Add("fa", "ba20f1f39af04b33780cb679f1b52d14925d37863c42aa32dbcd1ac0f85133b05f3a1aedace74411f9daa6b9d7e47680fa19a74e12947e1cbd52ff18d22c01db");
            result.Add("ff", "7c91a6f62e6aae07de94dc2808111c3144be18e67d03fe4603a65565fa1f9af1d4133d197a5764b2072b4c35e3c63f65ad48b27a47938468d06c4684b3a635d9");
            result.Add("fi", "ec05c78174eaf90a9fb0e945043432cb7b2acdea04efab983122a2693df30387af0baa93e217593ed5fc85a4dd2c74ba3d17a28c016329092f7bc3f996952130");
            result.Add("fr", "45b3448b7c4da7d380056fa15c82c275121fca91e764a67a39bf0c546481d0021c42487915d64aab10230be7c3061cb95c52d54f3e08d0894f06c2620678f467");
            result.Add("fy-NL", "e2c8793ee4e33a6b4a5c7d8849c034a1cbf129576ca13c46c68f9501684761f8b275de53b90066021f4f91c673d2e8a9848057a4a90975d0010b04df2cab762b");
            result.Add("ga-IE", "b655e45c69992d71eacbcab2013ac873bbbaefc554f0097c2a614071ab40ff4046ed9f2bd43559dbd6c5a24d79e6a0e8f2ffc99faf545decef77368ac5c5fc0c");
            result.Add("gd", "df267dae5daced7613f5ca6d6f2687fe1419199c51485994624600e9acad0ef9e8314349d4746805a99da38f92e3cfce5f21b82ebec6910363b13122573e788a");
            result.Add("gl", "2e46aa20e883a845fa1ca5b3f307edd92ed7d47f7767ff54b840ce9b600cd08e6a77337fab5d1169d8d6160d86bd2257f3bac0ec863c131e855793ccec03ce0e");
            result.Add("gn", "b9fbd6c08ea561e676978ffc5f51d967b08fb899face8a1bf0b3cbcd436dbfbe1dbbcb0caa088eaf438c34f710a96a9a586a2439eb4072edd93ae32fe95f8bd4");
            result.Add("gu-IN", "cec8eab060bcc3e53cee1408dc6de8746854f7bfc8f7a1e70ecfdbd9a6045889d267af146be46a93110f3f4c09f1edac41a1ebaf955a4d7e9c4caaa9e528b936");
            result.Add("he", "13d1f4f48d8702c182ce83ea3a8bc1200b24a730004e518a2176da6ce8530cd027189c81b2c9151edf0d1b0282e4e8089f484ad2242bcd152b904b004f31a1b3");
            result.Add("hi-IN", "f6e4de649c6a8401ca3525258a2e61178aa6e3f458ee304679dc31934fe778aa2292987401b90ecb0125d6190e9a3d5f96f48aba438f059a65417591c3a06603");
            result.Add("hr", "34d2a1eb8fdbb2b560ec6fbd2b151dff886b4c61f7e03346ff5cfc080f7bcc1256ac5597e62bb3a8fc0d20b6964df47cf42f36b1558e0f6defa251bf1ef759f0");
            result.Add("hsb", "21ee9219a3017ca4b016c54d4508587cfd899961869cec5f59666e1c3638b957568d5b46cb659ea195495afa9792969cbe2d3d525a45d905455a6686536ebee6");
            result.Add("hu", "1845ab5056715e4399829ddd2427a11aa6db74f9347ebcda5595ee08724d72af6b657370ecfcabe0dc45c713e68337b0f75e7502cab23e91eefd5262ca8d00df");
            result.Add("hy-AM", "363953e48d81a29be4b245a47b722dd73f8091ee6a7276848acc3625f4d4b72f5c031cb2555ce5a99940faae7b728846bd0b0dcdd0dee7f3b925505f0dd5d449");
            result.Add("ia", "d91b8b9a5ab538170ff811a4fca98f9aebe2e8e48a088c14e981289724a653f4b6c425081c3340ec211923f453386cccd48d8bb854daf08f123e26900e5f72ce");
            result.Add("id", "da91b9765416ef1c497d020d40014865de8ea0198d8f54ec0859bad5be2514126c48151f358c04860f08a6090e865162bf7f5623689c1c0a6d8bccd84ab02f2b");
            result.Add("is", "5426f58b71605f224b7fb4c8b961c10dd635d2eff1e316dd0d1262e85ba3479f54d39caa07b3285980e9361708e09c9116dbd200ab25e7be472ced942a88d015");
            result.Add("it", "4bf30c20c8cce33d19023dde2b11e61817704bf561fd1f06bf8a2dc35d45babe6ca602b3cbb9900b111d1f55f26774abb66a32416b2a52b28ffc1b33829e8446");
            result.Add("ja", "942fb040b3a12d6b7d3b9eeb1b62e27fc90c67ffbc739154b5849c94cc36c275b7351f5bc32969b3f2ba8c5597a2003a774ba9bd45296ba545bc2132ab213ecb");
            result.Add("ka", "f5b8d46f70863de1a420846ca41266c3c98ff57910b1fff00e2f47b08be52234466a9be7bc018ac49b5e81251fa2fed8d8ed17a49e6c1c0cfbec5ceda30fe5f4");
            result.Add("kab", "956aef55ed76fe0cae669ca652148df1f6321e3a8039eace8708576af6a1e26e71516413532f8a8290480b3105d8501a6c0570993ddfb5a12b122124d7acb5c8");
            result.Add("kk", "43edc8bf117d4265a71ecef7cccbf1d60854c4b574bf271fa8addb11cf3363077cc5ab6eba8c17d42829184beacd4b682cc68f0b08318725b0a42e026b523723");
            result.Add("km", "fb37495e993fb9286040b37e0756dc58fdd8181ff8b417757801f5342d2a25d232bc1883fe9b737fb47c0dd6c1b2e619d1b31d484d5116dc2267a14af18e1583");
            result.Add("kn", "5a8be86577aab0c3c6a4c905441d5f0dc7dab45f7588213ddea2e1a291adf6c98606c7f9f46fcbecc64197d082624fe4b10c16b5ad8b423325d35c48b3fa6223");
            result.Add("ko", "c1a28b590fc60b6625596c331cea0d4d9e7431d290e6d4a066698649d350cb6fae1e108eaa6f232ad83b5e39bff64a02433b5eff8d1afd64b106fab49c3070f9");
            result.Add("lij", "89d51bacd92d484372425aa2a241c7b40d9e53b7574a25ca46e84c28ed1991b66ac2c2fd28db1b0474155991efcc3a34d78e770f1d91266c49d47169e8f5b647");
            result.Add("lt", "d3d8df186ef64471ff77356634bb8ea9af5db6453dc6a69e9033c2e0edf3a4c28f39275feca3eaa802fbe9877665656c37be3e7625ab75d918521b0d3af5169a");
            result.Add("lv", "390c68f2a3f024474766801eab94bbceec4c5c2c936cf06931f6de42ed6583a019ebf9ae82cc229611349df5d6482f60b735e3bb9dc804315fbe952e5c2fae0c");
            result.Add("mk", "4f3742c151ad11c329338f7ab6fed5e91b4d4a8c6e35d76e4455e0b5ddc3085fde9ea272dfa3383155b031211aa33bb1821f67c70dac94dbdb5455f978bfefd4");
            result.Add("mr", "79c9d7e63b90c7af9c916f3b834d94c1bbfb4f79cd8c97bf2343c16376c3a885d393860d37ed80a50513c77cb54b79e2280642d63869e7017fa18c1953e8ffd9");
            result.Add("ms", "b3ffc1ad1be96efdd02eff5f0ea9199a7ba4f917f943d6af2be1274a9894b4363d1668f60e6e4ec8fd5703b49fcb33561cb68289cc7b4f0baf4c9b39602d4e6d");
            result.Add("my", "2d4308e44fca99b0081583b5658933390c2009f66f2d12a981d282ad1fa300cdd21ce5426ccc3a1c008b39e34294494e052cda88fce844274ec851979566f9f0");
            result.Add("nb-NO", "3cea1cdec1e65d136c986cbff803b126efe7a39196d7d6afad69fec96f50ce890232ecca098cc7b520a05dd980c8c6f6f25c323a4f980ce24720078d1b39ebb1");
            result.Add("ne-NP", "00a701bd1f91ac38fbbd5e2a567f6962b167b5af7374fe54a0dad41c902df3152ed4f5e64801853ba958a4a5d8f16f308f94fd1b72b695dea92ad105a6e3d612");
            result.Add("nl", "f76510c436e2f22898f649b33f04ff32e417786dd75039b3bd9b1c55f4e147470c3e6fdedd1bb1f543445401201fde939f6e0c856fb5d35e0f92919db6f7b3dd");
            result.Add("nn-NO", "163ccb41fb683973a7e7af9e7d275fad9616776850aa60a3f9afb073a941f767a59d8ea7663a7e1c8cd8dced2840f6bb3c2fcb270472ec46ca914fca370b3c01");
            result.Add("oc", "71bd2e4c74cfc83e0a931676a746c6c33caa50686d893e715ec58be543a7742fa9c831ff054ea4ad73b10e56d5e594b9103bcb64a30251c16cf041c7eb721454");
            result.Add("pa-IN", "a8f20b2694355b306b8ab377903dd579c3a28fde96a2451e204bda15b2400df708159435913bbbf60ce387807c427ecf2c7052cfa4583e69c17ddd040e657868");
            result.Add("pl", "54ed45f1878b62888fdd6200f8f40416a68fb9a014d53841769a83e8718390100b38045420414a1a1d33df4103b38ba82752d1542ee7292de6d2c2b3593508f2");
            result.Add("pt-BR", "68fb80427cae26470917e3ed42e383fede9047d6a01c324995da3dbb879a329a9a2b6c319440d77c44aca44c17bbaf58cb96e93dc5e657bf91059ac20bbc8155");
            result.Add("pt-PT", "b7b244b5fa01857c30c06a95906d96e7dffcf4df259f37a68986fbf9b6f1b8bb0bbabfd2eb9e24b43339c15ac6aedb2181e5d2146f6c7acb66ea1250b6d4a1c5");
            result.Add("rm", "492107adebe71e62abc146bbdc8da43168d1a022b4046bb17b181fbbd7dd100713c0ef173da332f3eb49d063989ba8be7c1c70b71beb2d1e425d92467578b6e6");
            result.Add("ro", "41f25453ebbc047308c9928308ee6cd1dde423ae139118773ca05876b9c449fcee4114bd3a6152905263abaf41bd2fb82caf3860e98b52d32b4d97961cdf80fa");
            result.Add("ru", "07a11921a7b20a75ddac8c152cf9370aaa88f04310c5008b23d63a33a9a76b35ba720907044523e1ad487635ed0eadad0228797bfb5c2e5d9e1ef29162c17983");
            result.Add("si", "d6d83800569ac8a616f44d6fc576504b49bdeed73c29d33affd6541658c0ef5703e10fa39396630f29cf66a79dfe44b4b37d06a6d54fbc50b8cc13f1153fb2e5");
            result.Add("sk", "bbe5c59eb2aac41b4f56eadca8bf3931e5d4c8e056b3ea766a1f6001619e4aade78355a4af3a51650c0ad7c9233eb7dfef052f527a135e36ab405c61a5ad6a04");
            result.Add("sl", "4802f5b79dde6daf01d2be3446ae447a1d473e1f2ec991b1a99a24526aeaabe0fd173173a4183ebb1c3d2e2b34eb42fa6eb47d07c25ccdad984388eb324e7f8c");
            result.Add("son", "e2b9e9303348f295dc8388cded2e69dee826affa959dd12904984a769124140fa9e977e0560ea05577ed8bd642c54c031e2214da22cc17191c3af1c02d35bc2f");
            result.Add("sq", "36d279de205b0821bc95eef87a1a83b910833f8479bdb17a29c71dd8ad329012d8c717e561167ffed44e32ac7608c8b4dfcae572c3073d6df73b1c85171221cb");
            result.Add("sr", "de701dadc740faece915b7600ed4244587ca81cc74411b0147f3cb590233125e0e1fe4a8cd7d8c2e054a135650d66f5e8497cd9c1c2fc8b8e86fb92c18e81c59");
            result.Add("sv-SE", "39feeefc275050a1068bbdc44b52e9bc4ebeb2b2856a3482f8529580d66995fada9f46ba2d1a235ae0d1d2dd61e0e7ac045d22b0ac3c03d83848005efc384de5");
            result.Add("ta", "263dee45cc465418216a8db2cde0b8eaa235e02952fe0d5b8c9ce30bbcfbe4d8dac21724eb9e2e4259c6eebfeb00f1a2f1c6da3488941cf01aa07ac7d6e6c563");
            result.Add("te", "f177c0be7b197c138c95a80a401ddf736dd41521649b7c59d3e3ca61cb2620ff43532d976ccdc0f2642f1b7de82a82867f7b906e3e18d44fa9e5eb6c288f3a12");
            result.Add("th", "be0655ce4da873e20fc3ffd327f5aff69161edeef6a888b965995df451bbe46194703338330ab11da64de845ca2ff9b730cbd4741edb64d2175cce4b658f8c7f");
            result.Add("tr", "82103a9f9bfd22397b4bd698b7ac192676e99f5b63357807fae825693a1a7f95c5c0adc51bdacb452a5351506bf8eaef0f6dfbc2397a27c67757b97f5f320917");
            result.Add("uk", "6b03ca8df5be088e8fdb0dcd1ce37d088fe928dfba4a9f8ac56bb10d6f3cdfd4ee79416825de9bb53fb37e1485cd781d242e4eb5953fd981d0c4022642a85af2");
            result.Add("ur", "9d373e43c33d95687b558e4a510536d261507a31a2db855ad3018d4fe219ce5c3441282465b7b13c242b98280260a53867e765f894e5c20201b748a4d3cf245c");
            result.Add("uz", "8fbba73949f8f36b7af036a986cd7082748ccfa0dc943b7704686a5c292173580f998f4514e83b33cf997de9b618cd4bc47c5109fd06a1ddcde5976ef7db598b");
            result.Add("vi", "a2af96b7496a6513d2546d91c46d43d75e584efa930a8948850aa12483b352310bc612a49b5b8834c3169e273135a7c6801e834594ff24c92b05cd19da15c9a4");
            result.Add("xh", "65920c42f42977db85110e191883d945b3c5e4a1e546903f2cddfdd2848f552214039b37dca7dc8a8cd7498da2ea7cb51c6fd5baa3d5717083245230f0d704e8");
            result.Add("zh-CN", "2df94f1517d4be401c7a09f8b924c5a0f14a7057ea659f974503e77c091adbc6e5f0e1acf46697bad76427eea3c9414030cdf4052cd20ba68e6383bc9ade9f3d");
            result.Add("zh-TW", "d82e99db640fa0488a34500d42e7942c232cf4d2abe13d98938de33c58ea8011547ef4c7b2ec91d888afda1eb4995a6595db80a64a579a0312915391466d46d7");

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
            const string knownVersion = "68.3.0";
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
