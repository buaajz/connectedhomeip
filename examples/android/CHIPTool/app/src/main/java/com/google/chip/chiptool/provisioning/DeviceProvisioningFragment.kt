/*
 *   Copyright (c) 2020 Project CHIP Authors
 *   All rights reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */

package com.google.chip.chiptool.provisioning

import android.bluetooth.BluetoothGatt
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import chip.devicecontroller.NetworkCredentials
import com.google.chip.chiptool.NetworkCredentialsParcelable
import com.google.chip.chiptool.ChipClient
import com.google.chip.chiptool.GenericChipDeviceListener
import com.google.chip.chiptool.R
import com.google.chip.chiptool.bluetooth.BluetoothManager
import com.google.chip.chiptool.setuppayloadscanner.CHIPDeviceInfo
import com.google.chip.chiptool.util.DeviceIdUtil
import com.google.chip.chiptool.util.FragmentUtil
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch

@ExperimentalCoroutinesApi
class DeviceProvisioningFragment : Fragment() {

  private lateinit var deviceInfo: CHIPDeviceInfo

  private var gatt: BluetoothGatt? = null

  private val networkCredentialsParcelable: NetworkCredentialsParcelable?
    get() = arguments?.getParcelable(ARG_NETWORK_CREDENTIALS)

  private lateinit var scope: CoroutineScope

  override fun onCreateView(
    inflater: LayoutInflater,
    container: ViewGroup?,
    savedInstanceState: Bundle?
  ): View {
    scope = viewLifecycleOwner.lifecycleScope
    deviceInfo = checkNotNull(requireArguments().getParcelable(ARG_DEVICE_INFO))
    return inflater.inflate(R.layout.single_fragment_container, container, false).apply {
      if (savedInstanceState == null) {
        if (deviceInfo.ipAddress != null) {
          pairDeviceWithAddress()
        } else {
          startConnectingToDevice()
        }
      }
    }
  }

  override fun onStop() {
    super.onStop()
    gatt = null
  }

  private fun pairDeviceWithAddress() {
    // IANA CHIP port
    val port = 5540
    val id = DeviceIdUtil.getNextAvailableId(requireContext())
    val deviceController = ChipClient.getDeviceController(requireContext())
    DeviceIdUtil.setNextAvailableId(requireContext(), id + 1)
    deviceController.setCompletionListener(ConnectionCallback())
    deviceController.pairDeviceWithAddress(
      id,
      deviceInfo.ipAddress,
      port,
      deviceInfo.discriminator,
      deviceInfo.setupPinCode,
      null
    )
  }

  private fun startConnectingToDevice() {
    if (gatt != null) {
      return
    }

    scope.launch {
      val deviceController = ChipClient.getDeviceController(requireContext())
      val bluetoothManager = BluetoothManager()

      showMessage(
        R.string.rendezvous_over_ble_scanning_text,
        deviceInfo.discriminator.toString()
      )
      val device = bluetoothManager.getBluetoothDevice(requireContext(), deviceInfo.discriminator) ?: run {
        showMessage(R.string.rendezvous_over_ble_scanning_failed_text)
        return@launch
      }

      showMessage(
        R.string.rendezvous_over_ble_connecting_text,
        device.name ?: device.address.toString()
      )
      gatt = bluetoothManager.connect(requireContext(), device)

      showMessage(R.string.rendezvous_over_ble_pairing_text)
      deviceController.setCompletionListener(ConnectionCallback())

      val deviceId = DeviceIdUtil.getNextAvailableId(requireContext())
      val connId = bluetoothManager.connectionId
      val network = NetworkCredentials()
      var networkParcelable = checkNotNull(networkCredentialsParcelable)

      val wifi = networkParcelable.getWiFiCredentials()
      if (wifi != null)
      {
        network.setWiFiCredentials(wifi.getSsid(), wifi.getPassword())
      }

      val thread = networkParcelable.getThreadCredentials()
      if (thread != null)
      {
        network.setThreadCredentials(thread.getOperationalDataset())
      }

      deviceController.pairDevice(gatt, connId, deviceId, deviceInfo.setupPinCode, network)
      DeviceIdUtil.setNextAvailableId(requireContext(), deviceId + 1)
    }
  }

  private fun showMessage(msgResId: Int, stringArgs: String? = null) {
    requireActivity().runOnUiThread {
      val context = requireContext()
      val msg = context.getString(msgResId, stringArgs)
      Log.i(TAG, "showMessage:$msg")
      Toast.makeText(context, msg, Toast.LENGTH_SHORT)
        .show()
    }
  }

  inner class ConnectionCallback : GenericChipDeviceListener() {
    override fun onConnectDeviceComplete() {
      Log.d(TAG, "onConnectDeviceComplete")
    }

    override fun onStatusUpdate(status: Int) {
      Log.d(TAG, "Pairing status update: $status")
    }

    override fun onCommissioningComplete(nodeId: Long, errorCode: Int) {
      if (errorCode == STATUS_PAIRING_SUCCESS) {
        FragmentUtil.getHost(this@DeviceProvisioningFragment, Callback::class.java)
          ?.onCommissioningComplete(0)
      } else {
        showMessage(R.string.rendezvous_over_ble_pairing_failure_text)
      }
    }

    override fun onPairingComplete(code: Int) {
      Log.d(TAG, "onPairingComplete: $code")

      if (code != STATUS_PAIRING_SUCCESS) {
        showMessage(R.string.rendezvous_over_ble_pairing_failure_text)
      }
    }

    override fun onOpCSRGenerationComplete(csr: ByteArray) {
      Log.d(TAG, String(csr))
    }

    override fun onPairingDeleted(code: Int) {
      Log.d(TAG, "onPairingDeleted: $code")
    }

    override fun onCloseBleComplete() {
      Log.d(TAG, "onCloseBleComplete")
    }

    override fun onError(error: Throwable?) {
      Log.d(TAG, "onError: $error")
    }
  }

  /** Callback from [DeviceProvisioningFragment] notifying any registered listeners. */
  interface Callback {
    /** Notifies that commissioning has been completed. */
    fun onCommissioningComplete(code: Int)
  }

  companion object {
    private const val TAG = "DeviceProvisioningFragment"
    private const val ARG_DEVICE_INFO = "device_info"
    private const val ARG_NETWORK_CREDENTIALS = "network_credentials"
    private const val STATUS_PAIRING_SUCCESS = 0

    /**
     * Return a new instance of [DeviceProvisioningFragment]. [networkCredentialsParcelable] can be null for
     * IP commissioning.
     */
    fun newInstance(
      deviceInfo: CHIPDeviceInfo,
      networkCredentialsParcelable: NetworkCredentialsParcelable?,
    ): DeviceProvisioningFragment {
      return DeviceProvisioningFragment().apply {
        arguments = Bundle(2).apply {
          putParcelable(ARG_DEVICE_INFO, deviceInfo)
          putParcelable(ARG_NETWORK_CREDENTIALS, networkCredentialsParcelable)
        }
      }
    }
  }
}
