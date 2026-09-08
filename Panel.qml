import QtQuick
import QtQuick.Controls as QQC
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

Panel {
  id: root

  moduleName: "io.github.drecullith.scope"
  ipcTarget: "io.github.drecullith.scope"

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color accentColor: Color.accent
  readonly property color urgentColor: Color.urgent
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  readonly property string helperPath: Qt.resolvedUrl("bin/scope-helper").toString().replace(/^file:\/\//, "")

  property bool active: false
  property var engagement: ({})
  property int selectedTargetIndex: 0
  property string setupKind: "lab"
  property bool actionBusy: false
  property string actionMode: ""
  property string feedback: ""
  property bool feedbackUrgent: false
  property string statusBuffer: ""
  property string actionBuffer: ""
  property string routeBuffer: ""
  property string urlBuffer: ""
  property var routeInfo: ({})
  property string elapsed: "00:00:00"

  readonly property var scopeRules: root.active && root.engagement && root.engagement.scope ? root.engagement.scope : []
  readonly property var targets: root.active && root.engagement && root.engagement.targets ? root.engagement.targets : []
  readonly property var quarantined: root.active && root.engagement && root.engagement.quarantine ? root.engagement.quarantine : []
  readonly property var timeline: root.active && root.engagement && root.engagement.timeline ? root.engagement.timeline : []
  readonly property string primaryTarget: root.active && root.engagement ? (root.engagement.primaryTarget || "") : ""
  readonly property string barTarget: root.primaryTarget.length > 18 ? root.primaryTarget.substring(0, 15) + "…" : root.primaryTarget
  readonly property var selectedTarget: root.targets.length > 0 && root.selectedTargetIndex >= 0 && root.selectedTargetIndex < root.targets.length
    ? root.targets[root.selectedTargetIndex]
    : null
  readonly property bool editing: nameField.activeFocus || scopeField.activeFocus || importPathField.activeFocus || noteField.activeFocus

  function parseJson(buffer) {
    try { return JSON.parse(buffer) }
    catch (e) { return null }
  }

  function setFeedback(message, urgent) {
    root.feedback = message || ""
    root.feedbackUrgent = !!urgent
    if (root.feedback !== "") feedbackTimer.restart()
  }

  function refreshStatus() {
    if (statusProc.running) return
    root.statusBuffer = ""
    statusProc.running = true
  }

  function refreshRoute() {
    if (!root.active || !root.primaryTarget || routeProc.running) {
      if (!root.primaryTarget) root.routeInfo = ({})
      return
    }
    root.routeBuffer = ""
    routeProc.command = [root.helperPath, "route", root.primaryTarget]
    routeProc.running = true
  }

  function runAction(mode, args) {
    if (root.actionBusy) return
    root.actionBusy = true
    root.actionMode = mode
    root.actionBuffer = ""
    actionProc.command = [root.helperPath].concat(args)
    actionProc.running = true
  }

  function startEngagement() {
    runAction("start", ["start", nameField.text, root.setupKind, scopeField.text])
  }

  function importNmap(path) {
    var value = (path || "").trim()
    if (value === "") {
      setFeedback("Choose or drop an Nmap XML file first", true)
      return
    }
    runAction("import", ["import-nmap", value])
  }

  function addNote() {
    var value = noteField.text.trim()
    if (value === "") return
    runAction("note", ["note", value])
  }

  function endEngagement() {
    runAction("end", ["end"])
  }

  function rebaselineRoute() {
    if (!root.primaryTarget) return
    runAction("route-baseline", ["route-baseline", root.primaryTarget])
  }

  function urlToPath(urlValue) {
    var value = String(urlValue || "")
    if (value.indexOf("file://") === 0) value = value.substring(7)
    try { value = decodeURIComponent(value) } catch (e) {}
    return value
  }

  function isWebService(service) {
    if (!service) return false
    var name = String(service.service || "").toLowerCase()
    var port = Number(service.port || 0)
    return name.indexOf("http") === 0 || port === 80 || port === 443 || port === 8080 || port === 8443
  }

  function serviceScheme(service) {
    var name = String(service.service || "").toLowerCase()
    var port = Number(service.port || 0)
    return name.indexOf("https") === 0 || port === 443 || port === 8443 ? "https" : "http"
  }

  function openService(target, service) {
    if (!target || !service || urlProc.running) return
    root.urlBuffer = ""
    urlProc.command = [root.helperPath, "url", target.address, serviceScheme(service), String(service.port)]
    urlProc.running = true
  }

  function copyText(value) {
    if (!value) return
    copyProc.command = ["wl-copy", String(value)]
    copyProc.running = true
    setFeedback("Copied", false)
  }

  function selectTarget(index) {
    if (index < 0 || index >= root.targets.length) return
    root.selectedTargetIndex = index
  }

  function setPrimaryTarget() {
    if (!root.selectedTarget) return
    runAction("primary", ["primary", root.selectedTarget.address])
  }

  function formatElapsed() {
    if (!root.active || !root.engagement || !root.engagement.startedAt) return "00:00:00"
    var start = new Date(root.engagement.startedAt).getTime()
    var seconds = Math.max(0, Math.floor((Date.now() - start) / 1000))
    var hours = Math.floor(seconds / 3600)
    var mins = Math.floor((seconds % 3600) / 60)
    var secs = seconds % 60
    function pad(n) { return n < 10 ? "0" + n : String(n) }
    return pad(hours) + ":" + pad(mins) + ":" + pad(secs)
  }

  function routeLabel() {
    var route = root.routeInfo && root.routeInfo.route ? root.routeInfo.route : null
    if (!route) return "Route not checked"
    if (route.verdict === "blocked") return "Route check blocked by scope"
    if (!route.known) return "Route UNKNOWN"
    var label = root.primaryTarget + " → " + (route.dev || "?")
    if (route.verdict === "match") return label + "  ✓"
    if (route.verdict === "changed") return label + "  ⚠ CHANGED"
    if (route.verdict === "unbaselined") return label + "  · unbaselined"
    return label
  }

  function routeUrgent() {
    var route = root.routeInfo && root.routeInfo.route ? root.routeInfo.route : null
    return !!route && route.verdict === "changed"
  }

  onOpenedChanged: {
    if (opened) {
      refreshStatus()
      Qt.callLater(function() { if (keyCatcher) keyCatcher.forceActiveFocus() })
    }
  }

  Component.onCompleted: refreshStatus()

  Timer {
    interval: 10000
    repeat: true
    running: true
    onTriggered: if (root.active) root.refreshStatus()
  }

  Timer {
    interval: 1000
    repeat: true
    running: root.active
    triggeredOnStart: true
    onTriggered: root.elapsed = root.formatElapsed()
  }

  Timer {
    id: feedbackTimer
    interval: 3500
    repeat: false
    onTriggered: root.feedback = ""
  }

  Process {
    id: statusProc
    command: [root.helperPath, "status"]
    stdout: SplitParser { onRead: function(data) { root.statusBuffer += data } }
    onExited: function(exitCode) {
      var res = root.parseJson(root.statusBuffer)
      root.statusBuffer = ""
      if (!res || res.status !== "ok") {
        root.setFeedback(res && res.message ? res.message : "SCOPE status unavailable", true)
        return
      }
      root.active = !!res.active
      root.engagement = res.engagement || ({})
      if (root.selectedTargetIndex >= root.targets.length) root.selectedTargetIndex = Math.max(0, root.targets.length - 1)
      root.elapsed = root.formatElapsed()
      if (root.active) Qt.callLater(root.refreshRoute)
      else root.routeInfo = ({})
    }
  }

  Process {
    id: actionProc
    stdout: SplitParser { onRead: function(data) { root.actionBuffer += data } }
    onExited: function(exitCode) {
      root.actionBusy = false
      var res = root.parseJson(root.actionBuffer)
      root.actionBuffer = ""
      if (!res || res.status !== "ok") {
        root.setFeedback(res && res.message ? res.message : "Action failed safely", true)
        return
      }
      if (root.actionMode === "import") {
        root.setFeedback(String(res.allowed || 0) + " in scope · " + String(res.quarantined || 0) + " quarantined", Number(res.quarantined || 0) > 0)
        importPathField.text = ""
      } else if (root.actionMode === "note") {
        noteField.text = ""
        root.setFeedback("Note added", false)
      } else if (root.actionMode === "start") {
        root.setFeedback("Engagement started", false)
      } else if (root.actionMode === "end") {
        root.setFeedback("Engagement ended", false)
      } else if (root.actionMode === "route-baseline") {
        root.setFeedback("Route baseline updated", false)
      } else if (root.actionMode === "primary") {
        root.setFeedback("Primary target updated", false)
      }
      root.refreshStatus()
    }
  }

  Process {
    id: routeProc
    stdout: SplitParser { onRead: function(data) { root.routeBuffer += data } }
    onExited: function(exitCode) {
      var res = root.parseJson(root.routeBuffer)
      root.routeBuffer = ""
      if (res && res.status === "ok") root.routeInfo = res
      else root.routeInfo = ({ route: { known: false, verdict: "unknown" } })
    }
  }

  Process {
    id: urlProc
    stdout: SplitParser { onRead: function(data) { root.urlBuffer += data } }
    onExited: function(exitCode) {
      var res = root.parseJson(root.urlBuffer)
      root.urlBuffer = ""
      if (!res || res.status !== "ok") {
        root.setFeedback(res && res.message ? res.message : "Could not validate target action", true)
        return
      }
      if (!res.allowed || !res.url) {
        root.setFeedback("OUT OF SCOPE — action refused", true)
        return
      }
      browserProc.command = ["xdg-open", res.url]
      browserProc.running = true
    }
  }

  Process { id: browserProc }
  Process { id: copyProc }

  implicitWidth: barButton.implicitWidth
  implicitHeight: barButton.implicitHeight

  WidgetButton {
    id: barButton
    anchors.fill: parent
    bar: root.bar
    text: root.active
      ? (root.barTarget !== "" ? "SCOPE · " + root.barTarget : "SCOPE · ACTIVE")
      : "SCOPE"
    active: root.active
    useActiveColor: false
    foreground: root.active ? root.accentColor : root.foreground
    fontSize: Style.font.bodySmall
    tooltipText: root.active && root.engagement
      ? (root.engagement.name + " · " + root.elapsed)
      : "SCOPE · authorized engagement HUD"

    onPressed: function(b) {
      if (b === Qt.RightButton) root.refreshStatus()
      else root.toggle()
    }
  }

  KeyboardPanel {
    id: popup
    anchorItem: barButton
    bar: root.bar
    owner: root
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: popup.fittedContentWidth(Style.space(560))
    contentHeight: popup.fittedContentHeight(Math.max(Style.space(320), Math.min(mainColumn.implicitHeight, Style.space(700))))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      blocked: root.editing
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(t) {
        if (root.editing) return
        if (t === "r" || t === "R") root.refreshStatus()
        else if ((t === "i" || t === "I") && root.active) importPathField.forceActiveFocus()
        else if ((t === "n" || t === "N") && root.active) noteField.forceActiveFocus()
      }

      Flickable {
        id: scroller
        anchors.fill: parent
        clip: true
        contentWidth: width
        contentHeight: mainColumn.implicitHeight
        boundsBehavior: Flickable.StopAtBounds
        interactive: contentHeight > height

        QQC.ScrollBar.vertical: QQC.ScrollBar { policy: QQC.ScrollBar.AsNeeded }

        Column {
          id: mainColumn
          width: scroller.width
          spacing: Style.space(10)

          // ------------------------------------------------------ HERO
          Item {
            width: parent.width
            implicitHeight: Math.max(heroMark.implicitHeight, heroLabels.implicitHeight, heroRefresh.implicitHeight)

            Text {
              id: heroMark
              text: "S"
              color: root.active ? root.accentColor : root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.display
              font.bold: true
              anchors.left: parent.left
              anchors.verticalCenter: parent.verticalCenter
            }

            Column {
              id: heroLabels
              anchors.left: heroMark.right
              anchors.leftMargin: Style.space(10)
              anchors.right: heroRefresh.left
              anchors.rightMargin: Style.space(8)
              anchors.verticalCenter: parent.verticalCenter
              spacing: Style.space(1)

              Text {
                width: parent.width
                text: root.active && root.engagement ? root.engagement.name : "SCOPE"
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.title
                font.bold: true
                elide: Text.ElideRight
              }

              Text {
                width: parent.width
                text: root.active && root.engagement
                  ? String(root.engagement.kind || "ENGAGEMENT").toUpperCase() + " · " + root.elapsed
                  : "AUTHORIZED ENGAGEMENT HUD"
                color: root.active ? root.accentColor : Qt.darker(root.foreground, 1.4)
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
                elide: Text.ElideRight
              }
            }

            Button {
              id: heroRefresh
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              iconText: root.actionBusy ? "󰑐" : "󰑐"
              iconSpinning: root.actionBusy
              tooltipText: "Refresh (r)"
              foreground: root.foreground
              fontFamily: root.fontFamily
              enabled: !root.actionBusy
              onClicked: root.refreshStatus()
            }
          }

          BorderSurface {
            visible: root.feedback !== ""
            width: parent.width
            implicitHeight: feedbackText.implicitHeight + Style.space(10)
            color: Style.hoverFillFor(root.foreground, root.feedbackUrgent ? root.urgentColor : root.accentColor)
            borderSpec: Border.controlSpec("hover-cursor", root.foreground, root.feedbackUrgent ? root.urgentColor : root.accentColor)
            radius: Style.cornerRadius

            Text {
              id: feedbackText
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              anchors.leftMargin: Style.space(10)
              anchors.rightMargin: Style.space(10)
              text: root.feedback
              color: root.feedbackUrgent ? root.urgentColor : root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: root.feedbackUrgent
              wrapMode: Text.Wrap
            }
          }

          // ------------------------------------------------------ SETUP
          Column {
            visible: !root.active
            width: parent.width
            spacing: Style.space(10)

            BorderSurface {
              width: parent.width
              implicitHeight: introText.implicitHeight + Style.space(16)
              color: Style.hoverFillFor(root.foreground, root.accentColor)
              borderSpec: Border.controlSpec("normal", root.foreground, root.accentColor)
              radius: Style.cornerRadius

              Text {
                id: introText
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                anchors.leftMargin: Style.space(12)
                anchors.rightMargin: Style.space(12)
                text: "SCOPE does not scan targets or install pentest tools. Define the authorization boundary first; everything SCOPE does after that is checked against it."
                color: root.foreground
                opacity: 0.85
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                wrapMode: Text.Wrap
              }
            }

            PanelSectionHeader {
              text: "New Engagement"
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            Text {
              text: "Name"
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: true
            }

            TextField {
              id: nameField
              width: parent.width
              placeholderText: "Boardlight"
              foreground: root.foreground
              accent: root.accentColor
              onAccepted: scopeField.forceActiveFocus()
            }

            Text {
              text: "Type"
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: true
            }

            Row {
              spacing: Style.space(6)
              Repeater {
                model: ["lab", "ctf", "client", "research"]
                Button {
                  required property string modelData
                  text: modelData.toUpperCase()
                  selected: root.setupKind === modelData
                  bordered: true
                  foreground: root.foreground
                  accent: root.accentColor
                  onClicked: root.setupKind = modelData
                }
              }
            }

            Text {
              text: "Authorization scope · one rule per line"
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: true
            }

            QQC.TextArea {
              id: scopeField
              width: parent.width
              height: Style.space(120)
              placeholderText: "10.10.11.42\n10.10.20.0/24\n*.example.com\n!admin.example.com"
              wrapMode: TextEdit.NoWrap
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              color: root.foreground
              selectionColor: Style.selectionFillFor(root.foreground, root.accentColor)
              selectedTextColor: root.foreground
              placeholderTextColor: Qt.darker(root.foreground, 1.6)
              leftPadding: Style.space(10)
              rightPadding: Style.space(10)
              topPadding: Style.space(8)
              bottomPadding: Style.space(8)
              background: BorderSurface {
                color: Style.controlFill(scopeField.activeFocus, scopeField.hovered, root.foreground, root.accentColor)
                borderSpec: Border.controlSpec(scopeField.activeFocus ? "focus" : (scopeField.hovered ? "hover-cursor" : "normal"), root.foreground, root.accentColor)
                radius: Style.cornerRadius
              }
            }

            Text {
              width: parent.width
              text: "Exact IPs, strict CIDRs, exact hostnames, *.wildcards, and !exclusions. Exclusions always win. Host bits in CIDRs are rejected instead of silently widening scope."
              color: Qt.darker(root.foreground, 1.45)
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.Wrap
            }

            Button {
              width: parent.width
              text: root.actionBusy ? "STARTING…" : "START ENGAGEMENT"
              iconText: "󰌾"
              active: true
              bordered: true
              foreground: root.foreground
              accent: root.accentColor
              enabled: !root.actionBusy
              onClicked: root.startEngagement()
            }

            Text {
              width: parent.width
              text: "No sudo · no firewall changes · no listeners · no automatic scans · no credentials · no attack automation"
              color: Qt.darker(root.foreground, 1.5)
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              horizontalAlignment: Text.AlignHCenter
              wrapMode: Text.Wrap
            }
          }

          // ------------------------------------------------------ ACTIVE HUD
          Column {
            visible: root.active
            width: parent.width
            spacing: Style.space(10)

            PanelSectionHeader {
              text: "Authorization"
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            BorderSurface {
              width: parent.width
              implicitHeight: authColumn.implicitHeight + Style.space(16)
              color: Style.hoverFillFor(root.foreground, root.accentColor)
              borderSpec: Border.controlSpec("hover-cursor", root.foreground, root.accentColor)
              radius: Style.cornerRadius

              Column {
                id: authColumn
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.leftMargin: Style.space(12)
                anchors.rightMargin: Style.space(12)
                anchors.topMargin: Style.space(8)
                spacing: Style.space(5)

                RowLayout {
                  width: parent.width
                  Text {
                    text: root.primaryTarget !== "" ? root.primaryTarget : "AWAITING TARGET"
                    color: root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.title
                    font.bold: true
                    Layout.fillWidth: true
                    elide: Text.ElideRight
                  }
                  Text {
                    text: root.primaryTarget !== "" ? "IN SCOPE ✓" : "SCOPE READY"
                    color: root.accentColor
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    font.bold: true
                  }
                }

                Flow {
                  width: parent.width
                  spacing: Style.space(5)
                  Repeater {
                    model: root.scopeRules
                    BorderSurface {
                      required property var modelData
                      implicitWidth: scopePillText.implicitWidth + Style.space(12)
                      implicitHeight: scopePillText.implicitHeight + Style.space(6)
                      color: Style.hoverFillFor(root.foreground, modelData.exclude ? root.urgentColor : root.accentColor)
                      borderSpec: Border.controlSpec("normal", root.foreground, modelData.exclude ? root.urgentColor : root.accentColor)
                      radius: Style.cornerRadius
                      Text {
                        id: scopePillText
                        anchors.centerIn: parent
                        text: modelData.raw
                        color: modelData.exclude ? root.urgentColor : root.foreground
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                      }
                    }
                  }
                }
              }
            }

            BorderSurface {
              width: parent.width
              implicitHeight: routeRow.implicitHeight + Style.space(12)
              color: Style.hoverFillFor(root.foreground, root.routeUrgent() ? root.urgentColor : root.accentColor)
              borderSpec: Border.controlSpec(root.routeUrgent() ? "hover-cursor" : "normal", root.foreground, root.routeUrgent() ? root.urgentColor : root.accentColor)
              radius: Style.cornerRadius

              RowLayout {
                id: routeRow
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                anchors.leftMargin: Style.space(10)
                anchors.rightMargin: Style.space(8)
                spacing: Style.space(8)

                Column {
                  Layout.fillWidth: true
                  spacing: Style.space(1)
                  Text {
                    text: "ROUTE GUARD"
                    color: root.routeUrgent() ? root.urgentColor : root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    font.bold: true
                  }
                  Text {
                    width: parent.width
                    text: root.routeLabel()
                    color: root.routeUrgent() ? root.urgentColor : Qt.darker(root.foreground, 1.25)
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.bodySmall
                    elide: Text.ElideRight
                  }
                }

                Button {
                  visible: root.primaryTarget !== ""
                  text: "CHECK"
                  foreground: root.foreground
                  accent: root.accentColor
                  onClicked: root.refreshRoute()
                }

                Button {
                  visible: root.routeInfo && root.routeInfo.route && root.routeInfo.route.known && (root.routeInfo.route.verdict === "changed" || root.routeInfo.route.verdict === "unbaselined")
                  text: "TRUST CURRENT"
                  foreground: root.foreground
                  accent: root.accentColor
                  bordered: true
                  enabled: !root.actionBusy
                  onClicked: root.rebaselineRoute()
                }
              }
            }

            PanelSectionHeader {
              text: "Targets"
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            Text {
              visible: root.targets.length === 0
              width: parent.width
              text: "No in-scope targets imported yet. Drop an Nmap XML result below; SCOPE will parse it but never run the scan itself."
              color: Qt.darker(root.foreground, 1.4)
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.Wrap
            }

            Column {
              visible: root.targets.length > 0
              width: parent.width
              spacing: Style.space(4)

              Repeater {
                model: root.targets
                CursorSurface {
                  required property var modelData
                  required property int index
                  width: parent.width
                  implicitHeight: targetRow.implicitHeight + Style.space(8)
                  hasCursor: root.selectedTargetIndex === index
                  current: root.selectedTargetIndex === index
                  foreground: root.foreground

                  MouseArea {
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.selectTarget(index)
                  }

                  RowLayout {
                    id: targetRow
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    anchors.leftMargin: Style.space(10)
                    anchors.rightMargin: Style.space(10)
                    spacing: Style.space(8)

                    Text {
                      text: modelData.address
                      color: root.foreground
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.body
                      font.bold: true
                      Layout.fillWidth: true
                    }
                    Text {
                      text: String(modelData.services ? modelData.services.length : 0) + " OPEN"
                      color: root.accentColor
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                      font.bold: true
                    }
                  }
                }
              }
            }

            BorderSurface {
              visible: root.selectedTarget !== null
              width: parent.width
              implicitHeight: selectedTargetColumn.implicitHeight + Style.space(16)
              color: Style.hoverFillFor(root.foreground, root.accentColor)
              borderSpec: Border.controlSpec("normal", root.foreground, root.accentColor)
              radius: Style.cornerRadius

              Column {
                id: selectedTargetColumn
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.leftMargin: Style.space(12)
                anchors.rightMargin: Style.space(12)
                anchors.topMargin: Style.space(8)
                spacing: Style.space(7)

                RowLayout {
                  width: parent.width
                  Text {
                    text: root.selectedTarget ? root.selectedTarget.address : ""
                    color: root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.subtitle
                    font.bold: true
                    Layout.fillWidth: true
                  }
                  Button {
                    visible: root.selectedTarget && root.selectedTarget.address !== root.primaryTarget
                    text: "MAKE PRIMARY"
                    foreground: root.foreground
                    accent: root.accentColor
                    bordered: true
                    enabled: !root.actionBusy
                    onClicked: root.setPrimaryTarget()
                  }
                  Button {
                    text: "COPY"
                    foreground: root.foreground
                    onClicked: if (root.selectedTarget) root.copyText(root.selectedTarget.address)
                  }
                }

                Text {
                  visible: root.selectedTarget && root.selectedTarget.hostnames && root.selectedTarget.hostnames.length > 0
                  width: parent.width
                  text: root.selectedTarget && root.selectedTarget.hostnames ? root.selectedTarget.hostnames.join(" · ") : ""
                  color: Qt.darker(root.foreground, 1.4)
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  elide: Text.ElideRight
                }

                Flow {
                  width: parent.width
                  spacing: Style.space(5)
                  Repeater {
                    model: root.selectedTarget && root.selectedTarget.services ? root.selectedTarget.services : []
                    Button {
                      required property var modelData
                      text: String(modelData.port) + "/" + String(modelData.protocol) + "  " + String(modelData.service || "unknown")
                      bordered: true
                      foreground: root.foreground
                      accent: root.accentColor
                      tooltipText: root.isWebService(modelData) ? "Scope-check and open in browser" : "Copy target:port"
                      onClicked: {
                        if (!root.selectedTarget) return
                        if (root.isWebService(modelData)) root.openService(root.selectedTarget, modelData)
                        else root.copyText(root.selectedTarget.address + ":" + String(modelData.port))
                      }
                    }
                  }
                }
              }
            }

            PanelSectionHeader {
              text: "Import Evidence"
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            BorderSurface {
              id: dropSurface
              width: parent.width
              implicitHeight: importColumn.implicitHeight + Style.space(16)
              color: importDrop.containsDrag
                ? Style.hoverFillFor(root.foreground, root.accentColor)
                : "transparent"
              borderSpec: Border.controlSpec(importDrop.containsDrag ? "hover-cursor" : "normal", root.foreground, root.accentColor)
              radius: Style.cornerRadius

              DropArea {
                id: importDrop
                anchors.fill: parent
                onDropped: function(drop) {
                  if (drop.urls && drop.urls.length > 0) {
                    var path = root.urlToPath(drop.urls[0])
                    importPathField.text = path
                    root.importNmap(path)
                    drop.acceptProposedAction()
                  }
                }
              }

              Column {
                id: importColumn
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.leftMargin: Style.space(10)
                anchors.rightMargin: Style.space(10)
                anchors.topMargin: Style.space(8)
                spacing: Style.space(6)

                Text {
                  width: parent.width
                  text: importDrop.containsDrag ? "DROP NMAP XML" : "Drop an Nmap XML file here — or enter a path. Imported hosts are scope-checked before they become actionable."
                  color: importDrop.containsDrag ? root.accentColor : root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.bodySmall
                  font.bold: importDrop.containsDrag
                  wrapMode: Text.Wrap
                }

                RowLayout {
                  width: parent.width
                  spacing: Style.space(6)
                  TextField {
                    id: importPathField
                    Layout.fillWidth: true
                    placeholderText: "/home/me/scans/boardlight.xml"
                    foreground: root.foreground
                    accent: root.accentColor
                    onAccepted: root.importNmap(text)
                  }
                  Button {
                    text: root.actionBusy && root.actionMode === "import" ? "IMPORTING…" : "IMPORT"
                    bordered: true
                    foreground: root.foreground
                    accent: root.accentColor
                    enabled: !root.actionBusy
                    onClicked: root.importNmap(importPathField.text)
                  }
                }
              }
            }

            Column {
              visible: root.quarantined.length > 0
              width: parent.width
              spacing: Style.space(6)

              PanelSectionHeader {
                text: "Quarantine"
                foreground: root.urgentColor
                fontFamily: root.fontFamily
              }

              BorderSurface {
                width: parent.width
                implicitHeight: quarantineColumn.implicitHeight + Style.space(14)
                color: Style.hoverFillFor(root.foreground, root.urgentColor)
                borderSpec: Border.controlSpec("hover-cursor", root.foreground, root.urgentColor)
                radius: Style.cornerRadius

                Column {
                  id: quarantineColumn
                  anchors.left: parent.left
                  anchors.right: parent.right
                  anchors.top: parent.top
                  anchors.leftMargin: Style.space(10)
                  anchors.rightMargin: Style.space(10)
                  anchors.topMargin: Style.space(7)
                  spacing: Style.space(4)

                  Text {
                    width: parent.width
                    text: "OUT OF SCOPE · ACTIONS DISABLED"
                    color: root.urgentColor
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    font.bold: true
                  }

                  Repeater {
                    model: root.quarantined
                    RowLayout {
                      required property var modelData
                      width: parent.width
                      Text {
                        text: "⛔ " + modelData.address
                        color: root.urgentColor
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.bodySmall
                        font.bold: true
                        Layout.fillWidth: true
                      }
                      Text {
                        text: String(modelData.services ? modelData.services.length : 0) + " services"
                        color: Qt.darker(root.foreground, 1.35)
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                      }
                    }
                  }
                }
              }
            }

            PanelSectionHeader {
              text: "Timeline"
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            RowLayout {
              width: parent.width
              spacing: Style.space(6)
              TextField {
                id: noteField
                Layout.fillWidth: true
                placeholderText: "Add a local engagement note…"
                foreground: root.foreground
                accent: root.accentColor
                onAccepted: root.addNote()
              }
              Button {
                text: "ADD"
                bordered: true
                foreground: root.foreground
                accent: root.accentColor
                enabled: !root.actionBusy
                onClicked: root.addNote()
              }
            }

            Column {
              width: parent.width
              spacing: Style.space(3)
              Repeater {
                model: root.timeline.slice(Math.max(0, root.timeline.length - 8)).reverse()
                RowLayout {
                  required property var modelData
                  width: parent.width
                  spacing: Style.space(7)
                  Text {
                    text: String(modelData.at || "").substring(11, 19)
                    color: Qt.darker(root.foreground, 1.55)
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                  }
                  Text {
                    text: modelData.message || ""
                    color: modelData.type === "scope" ? root.accentColor : root.foreground
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.bodySmall
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                  }
                }
              }
            }

            Button {
              width: parent.width
              text: root.actionBusy && root.actionMode === "end" ? "ENDING…" : "END ENGAGEMENT"
              bordered: true
              foreground: root.urgentColor
              accent: root.urgentColor
              enabled: !root.actionBusy
              onClicked: root.endEngagement()
            }

            Text {
              width: parent.width
              text: "SCOPE observes only its own state and explicitly imported evidence. It does not read shell history, terminal keystrokes, packet captures, or credentials."
              color: Qt.darker(root.foreground, 1.5)
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              horizontalAlignment: Text.AlignHCenter
              wrapMode: Text.Wrap
            }
          }
        }
      }
    }
  }
}
